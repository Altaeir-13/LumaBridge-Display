// Copyright 2026 LumaBridge Display Contributors
// SPDX-License-Identifier: Apache-2.0

//! RFC 9846 TLS 1.3-only mTLS configuration, custom Ed25519 self-signed certificate
//! verifiers, and RFC 9266 channel binding extraction.
//!
//! Security policy enforced on every TLS configuration:
//! - TLS 1.3 only (`TLS 1.2` disabled).
//! - TLS session resumption (tickets/PSK) and 0-RTT (`early_data`) explicitly disabled.
//! - Key logging (`SSLKEYLOGFILE` / `KeyLog`) explicitly disabled via `NoKeyLog`.
//! - Mutual authentication mandatory on both client and server.
//! - Every operational policy (`Trusted` and `PinnedPeer`) verifies live `TrustStore` state.

use crate::certificate::{
    verify_self_signed_ed25519_cert, GeneratedDeviceCertificate, VerifiedDeviceCertificate,
};
use crate::channel_binding::{extract_tls13_channel_binding, ChannelBinding};
use crate::error::SecurityError;
use crate::identity::{DeviceId, PeerRole, PublicIdentity};
use crate::trust_store::TrustStore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::Resumption;
use rustls::crypto::{verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::server::NoServerSessionStorage;
use rustls::{
    ClientConfig, ClientConnection, ConnectionCommon, DigitallySignedStruct, DistinguishedName,
    Error as RustlsError, HandshakeKind, NoKeyLog, ServerConfig, ServerConnection, SignatureScheme,
};
use std::io::{Read, Write};
use std::sync::Arc;

use lumabridge_protocol::version::{ALPN_OPERATIONAL_V1, ALPN_PAIRING_V1};

/// Operational ALPN identifier mandated for LBWP v1 over TLS 1.3.
pub const LUMABRIDGE_ALPN_V1: &[u8] = ALPN_OPERATIONAL_V1.as_bytes();

/// Pairing ALPN identifier mandated for LBWP v1 initial pairing over TLS 1.3.
pub const LUMABRIDGE_PAIR_ALPN_V1: &[u8] = ALPN_PAIRING_V1.as_bytes();

/// Peer trust verification mode enforced during the TLS 1.3 mTLS handshake.
#[derive(Clone)]
pub enum TlsPeerTrustPolicy {
    /// Initial pairing channel: requires valid self-signed Ed25519 X.509 v3 cert,
    /// rejects any revoked device via `trust_store`, and leaves final peer
    /// authentication to channel-bound SPAKE2 or QR token verification.
    Pairing { trust_store: Arc<dyn TrustStore> },
    /// Operational session channel: requires peer `DeviceId` to be explicitly trusted
    /// with `expected_role` and not revoked in `trust_store`.
    Trusted {
        trust_store: Arc<dyn TrustStore>,
        expected_role: PeerRole,
    },
    /// Pinned operational peer: requires BOTH exact `expected_device_id` match AND live
    /// non-revoked membership with `expected_role` in `trust_store`.
    PinnedPeer {
        trust_store: Arc<dyn TrustStore>,
        expected_role: PeerRole,
        expected_device_id: DeviceId,
    },
}

impl TlsPeerTrustPolicy {
    /// ALPN token required for connections under this policy.
    #[must_use]
    pub const fn expected_alpn(&self) -> &'static [u8] {
        match self {
            Self::Pairing { .. } => LUMABRIDGE_PAIR_ALPN_V1,
            Self::Trusted { .. } | Self::PinnedPeer { .. } => LUMABRIDGE_ALPN_V1,
        }
    }
}

/// Authenticated TLS 1.3 session metadata bound to peer certificate and RFC 9266 exporter.
///
/// Fields are private so application code cannot forge provenance or spoof `ChannelBinding`
/// outside [`extract_authenticated_session_with_alpn`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedTlsSession {
    peer_cert: VerifiedDeviceCertificate,
    channel_binding: ChannelBinding,
    negotiated_alpn: Vec<u8>,
}

impl AuthenticatedTlsSession {
    /// Construct a synthetic authenticated session strictly for unit tests and fuzz targets.
    #[cfg(any(test, feature = "test-utils"))]
    #[must_use]
    pub fn synthetic_for_testing(
        peer_cert: VerifiedDeviceCertificate,
        channel_binding: ChannelBinding,
        negotiated_alpn: Vec<u8>,
    ) -> Self {
        Self {
            peer_cert,
            channel_binding,
            negotiated_alpn,
        }
    }

    /// Validated peer X.509 certificate metadata.
    #[must_use]
    pub const fn peer_cert(&self) -> &VerifiedDeviceCertificate {
        &self.peer_cert
    }

    /// Validated canonical Ed25519 peer identity extracted from mTLS `CertificateVerify`.
    #[must_use]
    pub const fn peer_identity(&self) -> &PublicIdentity {
        &self.peer_cert.public_identity
    }

    /// RFC 9266 `EXPORTER-Channel-Binding` tied to this completed TLS 1.3 handshake.
    #[must_use]
    pub const fn channel_binding(&self) -> &ChannelBinding {
        &self.channel_binding
    }

    /// Negotiated TLS ALPN identifier.
    #[must_use]
    pub fn negotiated_alpn(&self) -> &[u8] {
        &self.negotiated_alpn
    }

    /// Returns `true` if the session negotiated the operational `"lumabridge/1"` ALPN.
    #[must_use]
    pub fn is_operational(&self) -> bool {
        self.negotiated_alpn.as_slice() == LUMABRIDGE_ALPN_V1
    }

    /// Returns `true` if the session negotiated the pairing `"lumabridge-pair/1"` ALPN.
    #[must_use]
    pub fn is_pairing(&self) -> bool {
        self.negotiated_alpn.as_slice() == LUMABRIDGE_PAIR_ALPN_V1
    }

    /// Ensure this session negotiated the operational `"lumabridge/1"` ALPN.
    pub fn require_operational_alpn(&self) -> Result<(), SecurityError> {
        if self.is_operational() {
            Ok(())
        } else {
            Err(SecurityError::AlpnMismatch)
        }
    }

    /// Ensure this session negotiated the pairing `"lumabridge-pair/1"` ALPN.
    pub fn require_pairing_alpn(&self) -> Result<(), SecurityError> {
        if self.is_pairing() {
            Ok(())
        } else {
            Err(SecurityError::AlpnMismatch)
        }
    }
}

/// Build a `rustls::ClientConfig` enforcing TLS 1.3-only mTLS (`lumabridge/1` or `lumabridge-pair/1`),
/// disabling TLS session resumption, 0-RTT early data, and `KeyLog`.
pub fn build_tls13_client_config(
    local_cert: &GeneratedDeviceCertificate,
    peer_policy: TlsPeerTrustPolicy,
) -> Result<Arc<ClientConfig>, SecurityError> {
    let alpn = peer_policy.expected_alpn().to_vec();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(LumaBridgeCertVerifier::new(&provider, peer_policy));

    let cert_chain = vec![CertificateDer::from(local_cert.cert_der.clone())];
    let key = PrivateKeyDer::try_from(local_cert.pkcs8_der.as_slice())
        .map_err(|_| SecurityError::TlsConfiguration("invalid client PKCS#8 private key"))?
        .clone_key();

    let mut cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| SecurityError::TlsConfiguration("failed to restrict client to TLS 1.3"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(cert_chain, key)
        .map_err(|_| SecurityError::TlsConfiguration("failed to configure client mTLS cert"))?;

    cfg.alpn_protocols = vec![alpn];
    cfg.resumption = Resumption::disabled();
    cfg.enable_early_data = false;
    cfg.key_log = Arc::new(NoKeyLog {});
    Ok(Arc::new(cfg))
}

/// Build a `rustls::ServerConfig` enforcing mandatory TLS 1.3-only mTLS (`lumabridge/1` or `lumabridge-pair/1`),
/// disabling TLS session tickets/PSK resumption, 0-RTT early data, and `KeyLog`.
pub fn build_tls13_server_config(
    local_cert: &GeneratedDeviceCertificate,
    peer_policy: TlsPeerTrustPolicy,
) -> Result<Arc<ServerConfig>, SecurityError> {
    let alpn = peer_policy.expected_alpn().to_vec();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = Arc::new(LumaBridgeCertVerifier::new(&provider, peer_policy));

    let cert_chain = vec![CertificateDer::from(local_cert.cert_der.clone())];
    let key = PrivateKeyDer::try_from(local_cert.pkcs8_der.as_slice())
        .map_err(|_| SecurityError::TlsConfiguration("invalid server PKCS#8 private key"))?
        .clone_key();

    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| SecurityError::TlsConfiguration("failed to restrict server to TLS 1.3"))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(cert_chain, key)
        .map_err(|_| SecurityError::TlsConfiguration("failed to configure server mTLS cert"))?;

    cfg.alpn_protocols = vec![alpn];
    cfg.send_tls13_tickets = 0;
    cfg.max_early_data_size = 0;
    cfg.session_storage = Arc::new(NoServerSessionStorage {});
    cfg.key_log = Arc::new(NoKeyLog {});
    Ok(Arc::new(cfg))
}

/// Inspect a completed TLS 1.3 connection, verify ALPN (`lumabridge/1`),
/// verify peer cert, reject any resumed session, and export RFC 9266 channel binding.
pub fn extract_authenticated_session<D>(
    conn: &ConnectionCommon<D>,
    now_unix_secs: u64,
) -> Result<AuthenticatedTlsSession, SecurityError> {
    extract_authenticated_session_with_alpn(conn, LUMABRIDGE_ALPN_V1, now_unix_secs)
}

/// Inspect a completed TLS 1.3 connection requiring `expected_alpn` (`lumabridge-pair/1` or `lumabridge/1`),
/// rejecting incomplete or resumed handshakes.
pub fn extract_authenticated_session_with_alpn<D>(
    conn: &ConnectionCommon<D>,
    expected_alpn: &[u8],
    now_unix_secs: u64,
) -> Result<AuthenticatedTlsSession, SecurityError> {
    if conn.is_handshaking() {
        return Err(SecurityError::TlsHandshakeFailed("handshake incomplete"));
    }
    if !matches!(
        conn.handshake_kind(),
        Some(HandshakeKind::Full | HandshakeKind::FullWithHelloRetryRequest)
    ) {
        return Err(SecurityError::TlsHandshakeFailed(
            "TLS session must complete a full non-resumed handshake",
        ));
    }
    let Some(alpn) = conn.alpn_protocol() else {
        return Err(SecurityError::AlpnMismatch);
    };
    if alpn != expected_alpn {
        return Err(SecurityError::AlpnMismatch);
    }
    let peer_certs = conn
        .peer_certificates()
        .ok_or(SecurityError::TlsHandshakeFailed(
            "peer did not present mTLS certificate",
        ))?;
    if peer_certs.len() != 1 {
        return Err(SecurityError::CertificateValidation(
            "expected single self-signed Ed25519 leaf certificate",
        ));
    }
    let peer_cert = verify_self_signed_ed25519_cert(peer_certs[0].as_ref(), now_unix_secs)?;
    let channel_binding = extract_tls13_channel_binding(conn)?;
    Ok(AuthenticatedTlsSession {
        peer_cert,
        channel_binding,
        negotiated_alpn: alpn.to_vec(),
    })
}

/// Inspect a completed QUIC (`quinn`) connection, verify ALPN (`lumabridge/1` or `lumabridge-pair/1`),
/// validate the peer self-signed Ed25519 mTLS certificate, and export RFC 9266 `tls-exporter`
/// channel binding directly from the active QUIC TLS 1.3 handshake.
///
/// Security invariant: callers MUST build `quinn` configs strictly via [`build_tls13_client_config`] /
/// [`build_tls13_server_config`] so TLS resumption and 0-RTT early data remain disabled.
#[cfg(feature = "quic")]
pub fn extract_authenticated_quic_session(
    conn: &quinn::Connection,
    expected_alpn: &[u8],
    now_unix_secs: u64,
) -> Result<AuthenticatedTlsSession, SecurityError> {
    let handshake_any = conn
        .handshake_data()
        .ok_or(SecurityError::TlsHandshakeFailed(
            "QUIC handshake incomplete",
        ))?;
    let handshake = handshake_any
        .downcast::<quinn::crypto::rustls::HandshakeData>()
        .map_err(|_| SecurityError::TlsHandshakeFailed("unexpected QUIC handshake provider"))?;
    let Some(alpn) = handshake.protocol else {
        return Err(SecurityError::AlpnMismatch);
    };
    if alpn.as_slice() != expected_alpn {
        return Err(SecurityError::AlpnMismatch);
    }

    let peer_any = conn
        .peer_identity()
        .ok_or(SecurityError::TlsHandshakeFailed(
            "QUIC peer did not present mTLS certificate",
        ))?;
    let peer_certs = peer_any
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| SecurityError::CertificateValidation("unexpected QUIC peer identity type"))?;
    if peer_certs.len() != 1 {
        return Err(SecurityError::CertificateValidation(
            "expected single self-signed Ed25519 leaf certificate",
        ));
    }
    let peer_cert = verify_self_signed_ed25519_cert(peer_certs[0].as_ref(), now_unix_secs)?;

    let mut out = zeroize::Zeroizing::new([0u8; crate::channel_binding::CHANNEL_BINDING_LEN]);
    conn.export_keying_material(
        out.as_mut(),
        crate::channel_binding::TLS_EXPORTER_CHANNEL_BINDING_LABEL,
        b"",
    )
    .map_err(|_| SecurityError::ChannelBindingMismatch)?;
    let channel_binding = ChannelBinding::from_tls13_exporter(*out);

    Ok(AuthenticatedTlsSession {
        peer_cert,
        channel_binding,
        negotiated_alpn: alpn,
    })
}

/// Construct a client `ServerName` placeholder for IP/LAN P2P connections authenticated by Ed25519 cert.
pub fn canonical_server_name_for_device(
    device_id: DeviceId,
) -> Result<ServerName<'static>, SecurityError> {
    let host = format!("lumabridge-{}.local", device_id.short_hex());
    ServerName::try_from(host)
        .map_err(|_| SecurityError::TlsConfiguration("invalid synthetic SNI name"))
}

/// Drive a real in-memory TLS 1.3 handshake between a client and server pair to completion.
pub fn drive_in_memory_handshake(
    client: &mut ClientConnection,
    server: &mut ServerConnection,
) -> Result<(), SecurityError> {
    let mut client_to_server = Vec::new();
    let mut server_to_client = Vec::new();
    let mut rounds = 0usize;

    while client.is_handshaking() || server.is_handshaking() {
        rounds += 1;
        if rounds > 32 {
            return Err(SecurityError::TlsHandshakeFailed(
                "handshake exceeded maximum round trips",
            ));
        }

        while client.wants_write() {
            client
                .write_tls(&mut client_to_server)
                .map_err(|_| SecurityError::TlsHandshakeFailed("client write_tls failed"))?;
        }
        if !client_to_server.is_empty() {
            let mut slice = client_to_server.as_slice();
            while !slice.is_empty() {
                server
                    .read_tls(&mut slice)
                    .map_err(|_| SecurityError::TlsHandshakeFailed("server read_tls failed"))?;
                server
                    .process_new_packets()
                    .map_err(|_| SecurityError::TlsHandshakeFailed("server handshake error"))?;
            }
            client_to_server.clear();
        }

        while server.wants_write() {
            server
                .write_tls(&mut server_to_client)
                .map_err(|_| SecurityError::TlsHandshakeFailed("server write_tls failed"))?;
        }
        if !server_to_client.is_empty() {
            let mut slice = server_to_client.as_slice();
            while !slice.is_empty() {
                client
                    .read_tls(&mut slice)
                    .map_err(|_| SecurityError::TlsHandshakeFailed("client read_tls failed"))?;
                client
                    .process_new_packets()
                    .map_err(|_| SecurityError::TlsHandshakeFailed("client handshake error"))?;
            }
            server_to_client.clear();
        }
    }

    // Flush any remaining post-handshake TLS control records (e.g., Finished ACK).
    for _ in 0..2 {
        while client.wants_write() {
            client
                .write_tls(&mut client_to_server)
                .map_err(|_| SecurityError::TlsHandshakeFailed("client flush failed"))?;
        }
        if !client_to_server.is_empty() {
            let mut slice = client_to_server.as_slice();
            while !slice.is_empty() {
                server
                    .read_tls(&mut slice)
                    .map_err(|_| SecurityError::TlsHandshakeFailed("server flush read failed"))?;
                server.process_new_packets().map_err(|_| {
                    SecurityError::TlsHandshakeFailed("server flush process failed")
                })?;
            }
            client_to_server.clear();
        }

        while server.wants_write() {
            server
                .write_tls(&mut server_to_client)
                .map_err(|_| SecurityError::TlsHandshakeFailed("server flush failed"))?;
        }
        if !server_to_client.is_empty() {
            let mut slice = server_to_client.as_slice();
            while !slice.is_empty() {
                client
                    .read_tls(&mut slice)
                    .map_err(|_| SecurityError::TlsHandshakeFailed("client flush read failed"))?;
                client.process_new_packets().map_err(|_| {
                    SecurityError::TlsHandshakeFailed("client flush process failed")
                })?;
            }
            server_to_client.clear();
        }
    }

    Ok(())
}

/// Transfer encrypted application bytes one way from writer `src` to reader `dst` in memory.
pub fn transfer_encrypted_app_data<S, D>(
    src: &mut ConnectionCommon<S>,
    dst: &mut ConnectionCommon<D>,
    plaintext: &[u8],
) -> Result<Vec<u8>, SecurityError> {
    src.writer()
        .write_all(plaintext)
        .map_err(|_| SecurityError::TlsHandshakeFailed("TLS plaintext write failed"))?;
    let mut wire = Vec::new();
    while src.wants_write() {
        src.write_tls(&mut wire)
            .map_err(|_| SecurityError::TlsHandshakeFailed("TLS write_tls failed"))?;
    }
    let mut slice = wire.as_slice();
    while !slice.is_empty() {
        dst.read_tls(&mut slice)
            .map_err(|_| SecurityError::TlsHandshakeFailed("TLS read_tls failed"))?;
        dst.process_new_packets()
            .map_err(|_| SecurityError::TlsHandshakeFailed("TLS process_new_packets failed"))?;
    }
    let mut out = vec![0u8; plaintext.len() + 64];
    let n = dst
        .reader()
        .read(&mut out)
        .map_err(|_| SecurityError::TlsHandshakeFailed("TLS plaintext read failed"))?;
    out.truncate(n);
    Ok(out)
}

#[derive(Debug)]
struct LumaBridgeCertVerifier {
    supported_algs: WebPkiSupportedAlgorithms,
    policy: TlsPeerTrustPolicy,
}

impl std::fmt::Debug for TlsPeerTrustPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pairing { .. } => f
                .debug_struct("Pairing")
                .field("has_trust_store", &true)
                .finish(),
            Self::Trusted { expected_role, .. } => f
                .debug_struct("Trusted")
                .field("expected_role", expected_role)
                .finish(),
            Self::PinnedPeer {
                expected_role,
                expected_device_id,
                ..
            } => f
                .debug_struct("PinnedPeer")
                .field("expected_role", expected_role)
                .field("expected_device_id", expected_device_id)
                .finish(),
        }
    }
}

impl LumaBridgeCertVerifier {
    fn new(provider: &CryptoProvider, policy: TlsPeerTrustPolicy) -> Self {
        Self {
            supported_algs: provider.signature_verification_algorithms,
            policy,
        }
    }

    fn verify_peer_end_entity(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<(), RustlsError> {
        if !intermediates.is_empty() {
            return Err(RustlsError::General(
                "unexpected intermediate certificates in P2P leaf identity mode".into(),
            ));
        }

        let verified = verify_self_signed_ed25519_cert(end_entity.as_ref(), now.as_secs())
            .map_err(|err| map_sec_to_rustls(&err))?;

        match &self.policy {
            TlsPeerTrustPolicy::Pairing { trust_store } => {
                if trust_store.is_revoked(verified.public_identity.device_id()) {
                    return Err(RustlsError::InvalidCertificate(
                        rustls::CertificateError::Revoked,
                    ));
                }
                Ok(())
            }
            TlsPeerTrustPolicy::Trusted {
                trust_store,
                expected_role,
            } => {
                trust_store
                    .verify_trusted_peer(&verified.public_identity, *expected_role)
                    .map_err(|err| map_sec_to_rustls(&err))?;
                Ok(())
            }
            TlsPeerTrustPolicy::PinnedPeer {
                trust_store,
                expected_role,
                expected_device_id,
            } => {
                if !verified
                    .public_identity
                    .device_id()
                    .ct_eq_id(expected_device_id)
                {
                    return Err(RustlsError::General(
                        "peer certificate device_id does not match pinned device_id".into(),
                    ));
                }
                trust_store
                    .verify_trusted_peer(&verified.public_identity, *expected_role)
                    .map_err(|err| map_sec_to_rustls(&err))?;
                Ok(())
            }
        }
    }
}

fn map_sec_to_rustls(err: &SecurityError) -> RustlsError {
    match err {
        SecurityError::CertificateExpired => {
            RustlsError::InvalidCertificate(rustls::CertificateError::Expired)
        }
        SecurityError::RevokedDevice => {
            RustlsError::InvalidCertificate(rustls::CertificateError::Revoked)
        }
        SecurityError::UntrustedDevice => {
            RustlsError::InvalidCertificate(rustls::CertificateError::UnknownIssuer)
        }
        _ => RustlsError::General(err.to_string()),
    }
}

impl ServerCertVerifier for LumaBridgeCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        self.verify_peer_end_entity(end_entity, intermediates, now)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::General(
            "TLS 1.2 is forbidden by LumaBridge security policy".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(RustlsError::General(
                "only Ed25519 TLS 1.3 handshake signatures are permitted".into(),
            ));
        }
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

impl ClientCertVerifier for LumaBridgeCertVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, RustlsError> {
        self.verify_peer_end_entity(end_entity, intermediates, now)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::General(
            "TLS 1.2 is forbidden by LumaBridge security policy".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(RustlsError::General(
                "only Ed25519 TLS 1.3 handshake signatures are permitted".into(),
            ));
        }
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }
}
