pub mod codec;
pub mod lcp;
pub mod ipcp;

use crate::error::{FortiError, Result};
use crate::tunnel::TlsTunnel;
use codec::{PppFrame, PppProtocol};
use ipcp::IpcpConfig;
use tracing::{debug, info};
use std::time::Duration;

/// PPP engine that drives LCP and IPCP negotiation over a TLS tunnel.
pub struct PppEngine {
    lcp: lcp::LcpState,
    ipcp: ipcp::IpcpState,
}

impl PppEngine {
    pub fn new(mru: u16) -> Self {
        Self {
            lcp: lcp::LcpState::new(mru),
            ipcp: ipcp::IpcpState::new(),
        }
    }

    /// Run full PPP negotiation: LCP → IPCP.
    /// Returns the negotiated IP configuration on success.
    pub async fn negotiate(&mut self, tunnel: &mut TlsTunnel) -> Result<IpcpConfig> {
        // Phase 1: LCP
        info!("Starting LCP negotiation");
        let lcp_req = self.lcp.build_configure_request();
        self.send_ppp(tunnel, PppProtocol::Lcp, lcp_req).await?;

        let mut lcp_done = false;
        let mut our_lcp_acked = false;
        let mut peer_lcp_acked = false;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        while !lcp_done {
            if tokio::time::Instant::now() > deadline {
                return Err(FortiError::PppError("LCP negotiation timeout".into()));
            }

            let frame = tokio::time::timeout(Duration::from_secs(10), tunnel.recv_frame())
                .await
                .map_err(|_| FortiError::PppError("timeout waiting for LCP response".into()))?
                ?;

            let ppp = PppFrame::decode(frame.payload())?;

            match ppp.protocol() {
                PppProtocol::Lcp => {
                    let responses = self.lcp.handle_packet(ppp.data());
                    for resp in &responses {
                        self.send_ppp(tunnel, PppProtocol::Lcp, resp.clone()).await?;
                    }

                    let code = ppp.data().first().copied().unwrap_or(0);
                    match code {
                        2 => { // Configure-Ack for our request
                            debug!("LCP: our Configure-Request accepted");
                            our_lcp_acked = true;
                        }
                        1 => { // Configure-Request from peer (we sent Ack or Reject)
                            if responses.iter().any(|r| r.first() == Some(&2)) {
                                debug!("LCP: peer Configure-Request accepted");
                                peer_lcp_acked = true;
                            }
                        }
                        _ => {}
                    }
                }
                PppProtocol::Ccp => {
                    // Reject CCP (compression) — send Protocol-Reject via LCP
                    debug!("Rejecting CCP Configure-Request");
                    let ccp_reject = build_protocol_reject(
                        PppProtocol::Ccp.to_u16(),
                        ppp.data(),
                    );
                    self.send_ppp(tunnel, PppProtocol::Lcp, ccp_reject).await?;
                }
                other => {
                    debug!("LCP phase: ignoring {:?} packet", other);
                }
            }

            lcp_done = our_lcp_acked && peer_lcp_acked;
        }

        info!("LCP negotiation complete");

        // Phase 2: IPCP
        info!("Starting IPCP negotiation");
        let ipcp_req = self.ipcp.build_configure_request();
        self.send_ppp(tunnel, PppProtocol::Ipcp, ipcp_req).await?;

        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);

        loop {
            if tokio::time::Instant::now() > deadline {
                return Err(FortiError::PppError("IPCP negotiation timeout".into()));
            }

            let frame = tokio::time::timeout(Duration::from_secs(10), tunnel.recv_frame())
                .await
                .map_err(|_| FortiError::PppError("timeout waiting for IPCP response".into()))?
                ?;

            let ppp = PppFrame::decode(frame.payload())?;

            match ppp.protocol() {
                PppProtocol::Ipcp => {
                    let responses = self.ipcp.handle_packet(ppp.data());
                    for resp in &responses {
                        self.send_ppp(tunnel, PppProtocol::Ipcp, resp.clone()).await?;
                    }

                    if let Some(config) = self.ipcp.config() {
                        info!("IPCP negotiation complete: IP={}", config.ip_address);
                        return Ok(config);
                    }
                }
                PppProtocol::Lcp => {
                    // Handle LCP packets during IPCP phase (keepalive, etc.)
                    let responses = self.lcp.handle_packet(ppp.data());
                    for resp in &responses {
                        self.send_ppp(tunnel, PppProtocol::Lcp, resp.clone()).await?;
                    }
                }
                other => {
                    debug!("IPCP phase: ignoring {:?} packet", other);
                }
            }
        }
    }

    async fn send_ppp(
        &self,
        tunnel: &mut TlsTunnel,
        protocol: PppProtocol,
        data: Vec<u8>,
    ) -> Result<()> {
        let ppp_frame = PppFrame::new(protocol, data);
        tunnel.send_frame(ppp_frame.encode()).await
    }
}

/// Build an LCP Protocol-Reject packet (code 8).
fn build_protocol_reject(rejected_protocol: u16, rejected_data: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&rejected_protocol.to_be_bytes());
    payload.extend_from_slice(rejected_data);

    if payload.len() > 1492 {
        payload.truncate(1492);
    }

    let length = (4 + payload.len()) as u16;
    let mut buf = Vec::with_capacity(4 + payload.len());
    buf.push(8); // Protocol-Reject code
    buf.push(0); // identifier
    buf.extend_from_slice(&length.to_be_bytes());
    buf.extend_from_slice(&payload);
    buf
}
