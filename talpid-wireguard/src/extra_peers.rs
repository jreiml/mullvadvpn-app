use std::{net::SocketAddr, sync::Weak, time::Duration};

use talpid_types::net::wireguard::ExtraPeerConfig;
use tokio::sync::Mutex as AsyncMutex;

use crate::{Tunnel, stats};

type TunnelType = Box<dyn Tunnel>;

const DEFAULT_RESOLVE_INTERVAL: Duration = Duration::from_secs(300);
const STALE_POLL_INTERVAL: Duration = Duration::from_secs(20);
const STALE_HANDSHAKE: Duration = Duration::from_secs(90);
const FORCED_RESOLVE_COOLDOWN: Duration = Duration::from_secs(60);

pub async fn run_manager(
    tunnel: Weak<AsyncMutex<Option<TunnelType>>>,
    extra_peers: Vec<ExtraPeerConfig>,
    refresh_rx: tokio::sync::watch::Receiver<u64>,
) {
    futures::future::join_all(
        extra_peers
            .into_iter()
            .map(|peer| run_peer_manager(tunnel.clone(), peer, refresh_rx.clone())),
    )
    .await;
}

async fn run_peer_manager(
    tunnel: Weak<AsyncMutex<Option<TunnelType>>>,
    peer: ExtraPeerConfig,
    mut refresh_rx: tokio::sync::watch::Receiver<u64>,
) {
    let resolve_interval = peer
        .resolve_interval_secs
        .map(Duration::from_secs)
        .filter(|interval| !interval.is_zero())
        .unwrap_or(DEFAULT_RESOLVE_INTERVAL);

    let mut resolve_tick = tokio::time::interval(resolve_interval);
    // Don't poll for staleness immediately — the peer can't be stale yet.
    let mut stale_tick = tokio::time::interval_at(
        tokio::time::Instant::now() + STALE_POLL_INTERVAL,
        STALE_POLL_INTERVAL,
    );
    let mut last_endpoint = None;
    let mut last_tx_bytes = 0u64;
    let mut last_forced_resolve = tokio::time::Instant::now() - FORCED_RESOLVE_COOLDOWN;

    resolve_and_update(&tunnel, &peer, &mut last_endpoint, false).await;

    loop {
        tokio::select! {
            _ = resolve_tick.tick() => {
                resolve_and_update(&tunnel, &peer, &mut last_endpoint, false).await;
            }
            Ok(()) = refresh_rx.changed() => {
                resolve_and_update(&tunnel, &peer, &mut last_endpoint, true).await;
            }
            _ = stale_tick.tick() => {
                let Some(stats) = peer_stats(&tunnel, &peer).await else {
                    continue;
                };
                let sent_new_packets = stats.tx_bytes > last_tx_bytes;
                last_tx_bytes = stats.tx_bytes;

                let stale = stats
                    .last_handshake_time
                    .and_then(|t| t.elapsed().ok())
                    .map(|elapsed| elapsed > STALE_HANDSHAKE)
                    .unwrap_or(true);

                if sent_new_packets
                    && stale
                    && last_forced_resolve.elapsed() >= FORCED_RESOLVE_COOLDOWN
                {
                    last_forced_resolve = tokio::time::Instant::now();
                    resolve_and_update(&tunnel, &peer, &mut last_endpoint, true).await;
                }
            }
        }
    }
}

async fn resolve_and_update(
    tunnel: &Weak<AsyncMutex<Option<TunnelType>>>,
    peer: &ExtraPeerConfig,
    last_endpoint: &mut Option<SocketAddr>,
    force_update: bool,
) {
    let Some(endpoint) = resolve_endpoint(peer).await else {
        return;
    };
    if !force_update && Some(endpoint) == *last_endpoint {
        return;
    }

    let Some(tunnel) = tunnel.upgrade() else {
        return;
    };
    let tunnel = tunnel.lock().await;
    let Some(tunnel) = tunnel.as_ref() else {
        return;
    };
    match tunnel.add_or_update_extra_peer(peer, endpoint).await {
        Ok(true) => {
            *last_endpoint = Some(endpoint);
            log::info!(
                "Added or updated extra WireGuard peer endpoint for {}",
                peer.public_key
            );
        }
        Ok(false) => log::warn!("Extra WireGuard peer {} was not found", peer.public_key),
        Err(error) => log::warn!("Failed to update extra WireGuard peer endpoint: {error}"),
    }
}

async fn resolve_endpoint(peer: &ExtraPeerConfig) -> Option<SocketAddr> {
    match tokio::net::lookup_host(&peer.endpoint).await {
        Ok(addrs) => {
            // Prefer IPv4 so that the endpoint matches the outbound socket family.
            let mut fallback = None;
            for addr in addrs {
                if addr.is_ipv4() {
                    return Some(addr);
                }
                fallback.get_or_insert(addr);
            }
            fallback
        }
        Err(error) => {
            log::warn!(
                "Failed to resolve extra WireGuard peer {}: {error}",
                peer.endpoint
            );
            None
        }
    }
}

async fn peer_stats(
    tunnel: &Weak<AsyncMutex<Option<TunnelType>>>,
    peer: &ExtraPeerConfig,
) -> Option<stats::Stats> {
    let tunnel = tunnel.upgrade()?;
    let tunnel = tunnel.lock().await;
    let tunnel = tunnel.as_ref()?;
    tunnel
        .get_tunnel_stats()
        .await
        .ok()?
        .get(peer.public_key.as_bytes())
        .cloned()
}
