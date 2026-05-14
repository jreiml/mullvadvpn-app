use std::{io, net::IpAddr, path::Path};

use ipnetwork::IpNetwork;
use talpid_types::net::wireguard::{ExtraPeerConfig, PresharedKey, PublicKey};

const EXTRA_PEERS_FILE: &str = "extra-peers.conf";

#[derive(Debug, Default)]
pub struct ExtraPeersConfig {
    pub addresses: Vec<IpAddr>,
    pub peers: Vec<ExtraPeerConfig>,
}

pub async fn load(settings_dir: &Path, allow_lan: bool) -> ExtraPeersConfig {
    if allow_lan {
        log::error!("Extra WireGuard peers require Local Network Sharing to be disabled");
        return ExtraPeersConfig::default();
    }

    let path = settings_dir.join(EXTRA_PEERS_FILE);
    let content = match tokio::fs::read_to_string(&path).await {
        Ok(content) => content,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return ExtraPeersConfig::default(),
        Err(error) => {
            log::warn!("Failed to read {}: {error}", path.display());
            return ExtraPeersConfig::default();
        }
    };

    match parse_conf(&content) {
        Ok(parsed) => ExtraPeersConfig {
            addresses: parsed.addresses.into_iter().map(|net| net.ip()).collect(),
            peers: parsed
                .peers
                .into_iter()
                .filter(|peer| {
                    let has_default_route = peer.allowed_ips.iter().any(|ip| ip.prefix() == 0);
                    if has_default_route {
                        log::error!(
                            "Ignoring extra WireGuard peer {} with default-route AllowedIPs",
                            peer.public_key
                        );
                    }
                    !has_default_route
                })
                .collect(),
        },
        Err(error) => {
            log::warn!("Failed to parse {}: {error}", path.display());
            ExtraPeersConfig::default()
        }
    }
}

struct ParsedConf {
    addresses: Vec<IpNetwork>,
    peers: Vec<ExtraPeerConfig>,
}

fn parse_conf(content: &str) -> Result<ParsedConf, String> {
    enum Section {
        Interface,
        Peer,
        Other,
    }

    let mut addresses = Vec::new();
    let mut peers = Vec::new();
    let mut section = Section::Other;
    let mut peer_builder: Option<PeerBuilder> = None;

    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim();
        let lineno = i + 1;

        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            if let Some(pb) = peer_builder.take() {
                peers.push(pb.build().map_err(|e| format!("line {lineno}: {e}"))?);
            }
            section = if line.eq_ignore_ascii_case("[Interface]") {
                Section::Interface
            } else if line.eq_ignore_ascii_case("[Peer]") {
                peer_builder = Some(PeerBuilder::default());
                Section::Peer
            } else {
                Section::Other
            };
            continue;
        }

        let Some((key, value)) = line.split_once('=').map(|(k, v)| (k.trim(), v.trim())) else {
            return Err(format!("line {lineno}: expected 'Key = Value'"));
        };

        match section {
            Section::Interface => {
                if key.eq_ignore_ascii_case("Address") {
                    let net = value
                        .parse::<IpNetwork>()
                        .map_err(|e| format!("line {lineno}: invalid Address '{value}': {e}"))?;
                    addresses.push(net);
                }
                // PrivateKey, DNS, ListenPort, etc. are intentionally ignored.
            }
            Section::Peer => {
                if let Some(ref mut pb) = peer_builder {
                    pb.set(key, value)
                        .map_err(|e| format!("line {lineno}: {e}"))?;
                }
            }
            Section::Other => {}
        }
    }

    if let Some(pb) = peer_builder.take() {
        peers.push(pb.build()?);
    }

    Ok(ParsedConf { addresses, peers })
}

#[derive(Default)]
struct PeerBuilder {
    public_key: Option<PublicKey>,
    allowed_ips: Vec<IpNetwork>,
    endpoint: Option<String>,
    psk: Option<PresharedKey>,
    persistent_keepalive_secs: Option<u16>,
}

impl PeerBuilder {
    fn set(&mut self, key: &str, value: &str) -> Result<(), String> {
        if key.eq_ignore_ascii_case("PublicKey") {
            self.public_key = Some(
                PublicKey::from_base64(value)
                    .map_err(|e| format!("invalid PublicKey: {e}"))?,
            );
        } else if key.eq_ignore_ascii_case("PresharedKey") {
            self.psk = Some(
                PresharedKey::from_base64(value)
                    .map_err(|e| format!("invalid PresharedKey: {e}"))?,
            );
        } else if key.eq_ignore_ascii_case("AllowedIPs") {
            for part in value.split(',') {
                let net = part
                    .trim()
                    .parse::<IpNetwork>()
                    .map_err(|e| format!("invalid AllowedIPs entry '{part}': {e}"))?;
                self.allowed_ips.push(net);
            }
        } else if key.eq_ignore_ascii_case("Endpoint") {
            self.endpoint = Some(value.to_owned());
        } else if key.eq_ignore_ascii_case("PersistentKeepalive") {
            self.persistent_keepalive_secs = Some(
                value
                    .parse::<u16>()
                    .map_err(|e| format!("invalid PersistentKeepalive: {e}"))?,
            );
        }
        // Unknown keys are silently ignored for forward compatibility.
        Ok(())
    }

    fn build(self) -> Result<ExtraPeerConfig, String> {
        let public_key = self.public_key.ok_or("missing PublicKey in [Peer]")?;
        let endpoint = self.endpoint.ok_or("missing Endpoint in [Peer]")?;
        if self.allowed_ips.is_empty() {
            return Err("missing AllowedIPs in [Peer]".into());
        }
        Ok(ExtraPeerConfig {
            public_key,
            allowed_ips: self.allowed_ips,
            endpoint,
            psk: self.psk,
            persistent_keepalive_secs: self.persistent_keepalive_secs,
            resolve_interval_secs: None,
        })
    }
}
