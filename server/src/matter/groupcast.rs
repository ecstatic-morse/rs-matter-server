//! Which network interfaces a Matter group's messages go out of.
//!
//! A group message is one IPv6 multicast datagram to the group's address.
//! Left to the kernel, it leaves by the first multicast route, which on a
//! host that is also a Thread border router is usually the Ethernet or Wi-Fi
//! interface. Thread members only hear it there if the border router forwards
//! it into the mesh, and it forwards only addresses some device registered
//! with it (Thread 1.2 multicast listener registration), which many devices
//! never do. Members on Wi-Fi or Ethernet, in turn, are never on the Thread
//! interface.
//!
//! So the datagram goes out of every interface that leads to a member: the
//! interface the kernel would use for a unicast to each member's operational
//! address. `group_command` works those out per group and records them in
//! [`GroupRoutes`]; [`GroupcastSend`], wrapped around the transport's UDP
//! sender, sends a datagram for a recorded group address out of each of its
//! interfaces in turn. The bytes are identical on every interface, so a member
//! that hears the message twice (on a network where the border router does
//! forward) drops the second copy as a duplicate counter.

use std::collections::{BTreeSet, HashMap};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, UdpSocket};
use std::sync::Mutex;

use async_io::Async;
use rs_matter::error::{Error, ErrorCode};
use rs_matter::transport::network::{Address, NetworkSend};

/// Hop limit for group datagrams. The kernel's multicast default is 1, which a
/// border router on another host could not forward past.
const HOP_LIMIT: u32 = 64;

/// Group multicast address → the interfaces (by index) its datagrams go out
/// of. Shared between the API, which fills it, and the transport, which reads
/// it on every send.
#[derive(Default)]
pub struct GroupRoutes {
    routes: Mutex<HashMap<Ipv6Addr, Vec<u32>>>,
}

impl GroupRoutes {
    /// Record `interfaces` for `group`; an empty list forgets the group, so its
    /// datagrams take the kernel's route.
    pub fn set(&self, group: Ipv6Addr, interfaces: Vec<u32>) {
        let mut routes = self.routes.lock().unwrap();
        if interfaces.is_empty() {
            routes.remove(&group);
        } else {
            routes.insert(group, interfaces);
        }
    }

    fn get(&self, group: &Ipv6Addr) -> Option<Vec<u32>> {
        self.routes.lock().unwrap().get(group).cloned()
    }
}

/// The interface the kernel would send a unicast to `address` out of, by
/// index: the scope of a link-local address, else the interface that owns the
/// source address a route lookup picks. `None` when nothing routes there.
pub fn interface_for(address: Ipv6Addr, scope_id: u32) -> Option<u32> {
    if address.is_unicast_link_local() {
        return (scope_id != 0).then_some(scope_id);
    }
    // Connecting a UDP socket sends nothing; it only makes the kernel pick a
    // route and a source address for the destination.
    let probe = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)).ok()?;
    probe
        .connect(SocketAddrV6::new(address, 5540, 0, scope_id))
        .ok()?;
    let SocketAddr::V6(local) = probe.local_addr().ok()? else {
        return None;
    };
    interface_owning(*local.ip())
}

/// The index of the interface that holds `address`.
fn interface_owning(address: Ipv6Addr) -> Option<u32> {
    nix::ifaddrs::getifaddrs()
        .ok()?
        .filter(|entry| {
            entry
                .address
                .as_ref()
                .and_then(|a| a.as_sockaddr_in6())
                .is_some_and(|a| a.ip() == address)
        })
        .find_map(|entry| nix::net::if_::if_nametoindex(entry.interface_name.as_str()).ok())
}

/// An address as the node store records it: `addr` or `addr%scope`, where
/// the scope is an interface name or index. IPv4 addresses are skipped:
/// Matter group messages are IPv6 only.
pub fn parse_address(text: &str) -> Option<(Ipv6Addr, u32)> {
    let (address, scope) = match text.split_once('%') {
        Some((address, scope)) => (address, Some(scope)),
        None => (text, None),
    };
    let address: Ipv6Addr = address.trim_matches(['[', ']']).parse().ok()?;
    let scope_id = match scope {
        None => 0,
        Some(scope) => scope
            .parse()
            .ok()
            .or_else(|| nix::net::if_::if_nametoindex(scope).ok())
            .unwrap_or(0),
    };
    Some((address, scope_id))
}

/// The distinct interfaces that lead to `addresses`, in index order.
pub fn interfaces_for<'a>(addresses: impl IntoIterator<Item = &'a str>) -> Vec<u32> {
    addresses
        .into_iter()
        .filter_map(parse_address)
        .filter_map(|(address, scope)| interface_for(address, scope))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

/// An interface's name, for logs and replies.
pub fn interface_name(index: u32) -> String {
    nix::net::if_::if_indextoname(index)
        .ok()
        .and_then(|name| name.into_string().ok())
        .unwrap_or_else(|| index.to_string())
}

/// A dedicated socket for group datagrams, so choosing their interface never
/// touches the main Matter socket. Group messages need no reply, so its port
/// doesn't matter.
pub fn bind_socket() -> std::io::Result<Async<UdpSocket>> {
    let socket = UdpSocket::bind(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))?;
    socket2::SockRef::from(&socket).set_multicast_hops_v6(HOP_LIMIT)?;
    Async::new(socket)
}

/// The transport's UDP sender, with group datagrams sent out of each of their
/// recorded interfaces through `socket`. Everything else goes to `inner`.
pub struct GroupcastSend<'a, S> {
    pub inner: S,
    pub socket: &'a Async<UdpSocket>,
    pub routes: &'a GroupRoutes,
}

impl<S: NetworkSend> NetworkSend for GroupcastSend<'_, S> {
    async fn send_to(&mut self, data: &[u8], addr: Address) -> Result<(), Error> {
        let interfaces = match addr.udp() {
            Some(SocketAddr::V6(target)) if target.ip().is_multicast() => {
                self.routes.get(target.ip()).map(|i| (target, i))
            }
            _ => None,
        };
        let Some((target, interfaces)) = interfaces else {
            return self.inner.send_to(data, addr).await;
        };

        // Sends are one at a time (the transport holds `&mut self`), and only
        // this sender uses the socket, so setting its interface before each
        // send can't race another.
        let mut sent = 0;
        for &index in &interfaces {
            let result =
                match socket2::SockRef::from(self.socket.get_ref()).set_multicast_if_v6(index) {
                    Ok(()) => self
                        .socket
                        .send_to(data, SocketAddr::V6(target))
                        .await
                        .map(|_| ()),
                    Err(e) => Err(e),
                };
            match result {
                Ok(()) => sent += 1,
                Err(e) => log::warn!(
                    "Group datagram to {} out of {} failed: {}",
                    target.ip(),
                    interface_name(index),
                    e
                ),
            }
        }
        if sent == 0 {
            return Err(ErrorCode::NoNetworkInterface.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_parse_with_or_without_a_scope() {
        assert_eq!(
            parse_address("fdd2:cff4:6c2:1::5"),
            Some(("fdd2:cff4:6c2:1::5".parse().unwrap(), 0))
        );
        assert_eq!(
            parse_address("fe80::1%7"),
            Some(("fe80::1".parse().unwrap(), 7))
        );
        assert_eq!(parse_address("192.168.0.9"), None);
        assert_eq!(parse_address("not an address"), None);
    }

    #[test]
    fn loopback_routes_to_the_loopback_interface() {
        let lo = nix::net::if_::if_nametoindex("lo").unwrap();
        assert_eq!(interface_for(Ipv6Addr::LOCALHOST, 0), Some(lo));
        assert_eq!(interfaces_for(["::1", "::1"]), vec![lo]);
        // A link-local address names its interface itself.
        assert_eq!(interface_for("fe80::1".parse().unwrap(), 3), Some(3));
        assert_eq!(interface_for("fe80::1".parse().unwrap(), 0), None);
    }

    #[test]
    fn unrecorded_groups_take_the_kernel_route() {
        let routes = GroupRoutes::default();
        let group: Ipv6Addr = "ff35:40:fd00::100:7e01".parse().unwrap();
        assert_eq!(routes.get(&group), None);
        routes.set(group, vec![2, 5]);
        assert_eq!(routes.get(&group), Some(vec![2, 5]));
        routes.set(group, vec![]);
        assert_eq!(routes.get(&group), None);
    }
}
