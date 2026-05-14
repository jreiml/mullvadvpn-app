use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
    tun::tun_async_device::TunDevice as GotaTunDevice,
};
use ipnetwork::IpNetwork;
use tokio::sync::mpsc;

use crate::config::Config;

/// SNAT configuration derived from the WireGuard config.
#[derive(Clone)]
pub struct SnatConfig {
    /// The extra IPv4 address to use as the source for extra-peer-bound packets.
    extra_addr_v4: Option<Ipv4Addr>,
    /// The primary VPN IPv4 address (reverse SNAT: rewrite dst back to this).
    primary_addr_v4: Option<Ipv4Addr>,
    /// IPv4 allowed-IPs from all extra peers — packets to these are SNAT'd.
    extra_peer_nets: Vec<IpNetwork>,
}

impl SnatConfig {
    pub fn from_config(config: &Config) -> Self {
        // The daemon merges extra addresses into tunnel.addresses via extend(), so the
        // Mullvad VPN address is always first; extra peer addresses follow.
        let mut ipv4_addrs = config.tunnel.addresses.iter().filter_map(|ip| match ip {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        });

        let primary_addr_v4 = ipv4_addrs.next();
        let extra_addr_v4 = ipv4_addrs.next(); // first extra IPv4 address, if any

        let extra_peer_nets = config
            .extra_peers
            .iter()
            .flat_map(|peer| peer.allowed_ips.iter().cloned())
            .filter(|net| net.is_ipv4())
            .collect();

        SnatConfig {
            primary_addr_v4,
            extra_addr_v4,
            extra_peer_nets,
        }
    }

    fn active_addrs(&self) -> Option<(Ipv4Addr, Ipv4Addr)> {
        if self.extra_peer_nets.is_empty() {
            return None;
        }
        Some((self.extra_addr_v4?, self.primary_addr_v4?))
    }
}

/// Wraps a tun device to perform SNAT for extra WireGuard peer traffic.
///
/// Outbound (tun → WireGuard): if dst is in any extra peer's allowed-IPs, rewrites
/// src from the primary Mullvad VPN IP to the extra peer address.
///
/// Inbound (WireGuard → tun): if dst is the extra address, rewrites it back to
/// the primary VPN IP so the kernel delivers it to the originating socket.
#[derive(Clone)]
pub struct SnatTunDevice<T: Clone> {
    inner: T,
    config: SnatConfig,
}

impl<T: Clone> SnatTunDevice<T> {
    pub fn new(inner: T, config: SnatConfig) -> Self {
        SnatTunDevice { inner, config }
    }
}

impl<T: IpSend + Clone> IpSend for SnatTunDevice<T> {
    async fn send(&mut self, packet: Packet<Ip>) -> std::io::Result<()> {
        let packet = snat_inbound(packet, &self.config);
        self.inner.send(packet).await
    }
}

impl<T: IpRecv + Clone> IpRecv for SnatTunDevice<T> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> std::io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packets = self.inner.recv(pool).await?;
        let config = &self.config;
        let processed: Vec<Packet<Ip>> = packets.map(|p| snat_outbound(p, config)).collect();
        Ok(processed.into_iter())
    }

    fn mtu(&self) -> MtuWatcher {
        self.inner.mtu()
    }
}

/// Outbound path (tun → WireGuard peer): rewrite src to the extra peer address.
pub(super) fn snat_outbound(packet: Packet<Ip>, config: &SnatConfig) -> Packet<Ip> {
    let Some((extra_addr, _)) = config.active_addrs() else {
        return packet;
    };

    let mut raw = packet.into_bytes();
    {
        let bytes: &mut [u8] = raw.buf_mut();
        if is_ipv4_with_len(bytes, 20) {
            let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
            if config
                .extra_peer_nets
                .iter()
                .any(|net| net.contains(IpAddr::V4(dst)))
            {
                let old_src = Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]);
                if old_src != extra_addr {
                    rewrite_ipv4_src(bytes, old_src, extra_addr);
                }
            }
        }
    }
    raw.try_into_ip().expect("packet was valid before SNAT")
}

/// Inbound path (WireGuard peer → tun): rewrite dst back to the primary VPN address.
pub(super) fn snat_inbound(packet: Packet<Ip>, config: &SnatConfig) -> Packet<Ip> {
    let Some((extra_addr, primary_addr)) = config.active_addrs() else {
        return packet;
    };

    let mut raw = packet.into_bytes();
    {
        let bytes: &mut [u8] = raw.buf_mut();
        if is_ipv4_with_len(bytes, 20) {
            let dst = Ipv4Addr::new(bytes[16], bytes[17], bytes[18], bytes[19]);
            if dst == extra_addr {
                rewrite_ipv4_dst(bytes, extra_addr, primary_addr);
            }
        }
    }
    raw.try_into_ip().expect("packet was valid before reverse SNAT")
}

fn is_ipv4_with_len(bytes: &[u8], min_len: usize) -> bool {
    bytes.len() >= min_len && (bytes[0] >> 4) == 4
}

/// Rewrite src address and update IP + transport checksums.
fn rewrite_ipv4_src(bytes: &mut [u8], old_addr: Ipv4Addr, new_addr: Ipv4Addr) {
    let ihl = (bytes[0] & 0x0f) as usize * 4;
    let protocol = bytes[9];
    if bytes.len() > ihl {
        update_transport_csum_v4(&mut bytes[ihl..], protocol, old_addr, new_addr);
    }
    let old_csum = u16::from_be_bytes([bytes[10], bytes[11]]);
    bytes[12..16].copy_from_slice(&new_addr.octets());
    let new_csum = update_addr_in_checksum(old_csum, old_addr, new_addr);
    bytes[10..12].copy_from_slice(&new_csum.to_be_bytes());
}

/// Rewrite dst address and update IP + transport checksums.
fn rewrite_ipv4_dst(bytes: &mut [u8], old_addr: Ipv4Addr, new_addr: Ipv4Addr) {
    let ihl = (bytes[0] & 0x0f) as usize * 4;
    let protocol = bytes[9];
    if bytes.len() > ihl {
        update_transport_csum_v4(&mut bytes[ihl..], protocol, old_addr, new_addr);
    }
    let old_csum = u16::from_be_bytes([bytes[10], bytes[11]]);
    bytes[16..20].copy_from_slice(&new_addr.octets());
    let new_csum = update_addr_in_checksum(old_csum, old_addr, new_addr);
    bytes[10..12].copy_from_slice(&new_csum.to_be_bytes());
}

/// Update TCP or UDP checksum after an IP address change.
/// ICMP is skipped because its checksum does not cover the IP pseudo-header.
fn update_transport_csum_v4(transport: &mut [u8], protocol: u8, old_addr: Ipv4Addr, new_addr: Ipv4Addr) {
    let csum_offset = match protocol {
        6 if transport.len() >= 18 => 16,  // TCP
        17 if transport.len() >= 8 => {
            if transport[6] == 0 && transport[7] == 0 {
                return; // UDP checksum disabled (IPv4 allows this)
            }
            6 // UDP
        }
        _ => return,
    };
    let old_csum = u16::from_be_bytes([transport[csum_offset], transport[csum_offset + 1]]);
    let new_csum = update_addr_in_checksum(old_csum, old_addr, new_addr);
    transport[csum_offset..csum_offset + 2].copy_from_slice(&new_csum.to_be_bytes());
}

/// RFC 1624 incremental checksum update after replacing a 32-bit IP address.
///
/// HC' = ~(~HC + ~m + m')  applied once per 16-bit word of the address.
fn update_addr_in_checksum(old_csum: u16, old_addr: Ipv4Addr, new_addr: Ipv4Addr) -> u16 {
    let old = old_addr.octets();
    let new = new_addr.octets();

    let mut sum = u32::from(!old_csum); // ~HC
    sum = fold_add(sum, u32::from(u16::from_be_bytes([old[0], old[1]]) ^ 0xffff)); // ~m1
    sum = fold_add(sum, u32::from(u16::from_be_bytes([old[2], old[3]]) ^ 0xffff)); // ~m2
    sum = fold_add(sum, u32::from(u16::from_be_bytes([new[0], new[1]]))); // m1'
    sum = fold_add(sum, u32::from(u16::from_be_bytes([new[2], new[3]]))); // m2'

    !(sum as u16)
}

/// Ones-complement addition with carry folded back in.
fn fold_add(a: u32, b: u32) -> u32 {
    let s = a + b;
    (s >> 16) + (s & 0xffff)
}

/// Return `true` if the packet's destination IP is covered by one of `nets`.
pub(super) fn is_extra_peer_dest(packet: &Packet<Ip>, nets: &[IpNetwork]) -> bool {
    let Some(dst) = packet.destination() else {
        return false;
    };
    nets.iter().any(|net| net.contains(dst))
}

/// Number of pending packets buffered for the extra-peer device.
pub(super) const EXTRA_PEER_CHANNEL_CAPACITY: usize = 128;

// ---------------------------------------------------------------------------
// Tun adapters used by the separate extra-peer device
// ---------------------------------------------------------------------------

/// [`IpSend`] for the extra-peer device: applies inbound SNAT and writes to
/// the real tun fd so the application receives packets at its primary VPN IP.
pub(super) struct ExtraPeerTunSend {
    pub inner: GotaTunDevice,
    pub snat_config: SnatConfig,
}

impl IpSend for ExtraPeerTunSend {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let packet = snat_inbound(packet, &self.snat_config);
        self.inner.send(packet).await
    }
}

/// [`IpRecv`] for the extra-peer device: receives raw packets from a channel
/// (fed by [`FilteredTunRecv`]) and applies outbound SNAT before encryption.
pub(super) struct ExtraPeerTunRecv {
    pub rx: mpsc::Receiver<Packet<Ip>>,
    pub snat_config: SnatConfig,
    pub mtu: u16,
}

impl IpRecv for ExtraPeerTunRecv {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packet = self
            .rx
            .recv()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "extra-peer channel closed"))?;
        let packet = snat_outbound(packet, &self.snat_config);
        Ok(std::iter::once(packet))
    }

    fn mtu(&self) -> MtuWatcher {
        MtuWatcher::new(self.mtu)
    }
}

/// [`IpRecv`] for the main (Mullvad relay) device when extra peers are present.
///
/// Reads packets from the real tun fd and dispatches extra-peer-bound packets
/// to `extra_tx` so the separate extra-peer device can handle them.  All other
/// packets are returned to the main device for encryption towards the relay.
pub(super) struct FilteredTunRecv {
    pub inner: GotaTunDevice,
    /// All allowed-IP prefixes that belong to extra peers (IPv4 and IPv6).
    pub extra_peer_nets: Vec<IpNetwork>,
    pub extra_tx: mpsc::Sender<Packet<Ip>>,
}

impl IpRecv for FilteredTunRecv {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        loop {
            let packets = self.inner.recv(pool).await?;
            let mut main_packets: Vec<Packet<Ip>> = Vec::new();
            for packet in packets {
                if is_extra_peer_dest(&packet, &self.extra_peer_nets) {
                    // Best-effort: drop the packet if the channel is full.
                    let _ = self.extra_tx.try_send(packet);
                } else {
                    main_packets.push(packet);
                }
            }
            if !main_packets.is_empty() {
                return Ok(main_packets.into_iter());
            }
            // All packets went to extra peers; read again.
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.inner.mtu()
    }
}
