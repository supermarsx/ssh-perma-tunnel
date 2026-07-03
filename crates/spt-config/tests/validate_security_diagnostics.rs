//! Regression coverage for security-relevant `validate()` diagnostic **codes**.
//!
//! Motivation (cov-board 26.46, Config P0 #3): ~90 of 192 `validate()`
//! diagnostics had no test asserting the *specific* code fires for its trigger
//! config. A security gate could therefore regress to silent-accept with zero
//! test failures.
//!
//! Each test here pins a security / fail-closed / gate diagnostic with a
//! **fire** case (a config that must trigger the exact code) and a **no-fire**
//! case (a valid config where the code must be absent). If the gate stops
//! firing on its trigger, the fire assertion fails; if it starts firing
//! spuriously, the no-fire assertion fails.
//!
//! Codes intentionally NOT covered here (lower-value shape/enum diagnostics,
//! already-covered honesty codes, or platform-gated ones) are enumerated in the
//! run log `.orchestration/logs/tw-configval.md`.

use spt_config::{load_str, validate, ValidationDiagnostics};

/// Parse `raw` (non-strict) and run semantic validation. Panics if the TOML
/// itself fails to parse — every fixture below is valid TOML by construction.
fn diags(raw: &str) -> ValidationDiagnostics {
    let (c, _warnings) = load_str(raw, false).expect("fixture TOML must parse");
    validate(&c)
}

/// `true` when an ERROR-severity diagnostic with `code` is present.
fn has_error(raw: &str, code: &str) -> bool {
    diags(raw).errors.iter().any(|e| e.code == code)
}

/// `true` when a WARNING-severity diagnostic with `code` is present.
fn has_warning(raw: &str, code: &str) -> bool {
    diags(raw).warnings.iter().any(|w| w.code == code)
}

// ---------------------------------------------------------------------------
// Forward bind exposure gates (spec §9.14)
// ---------------------------------------------------------------------------

#[test]
fn wildcard_bind_without_expose_fires_and_clears() {
    // FIRE: a wildcard (0.0.0.0) bind without `expose = true` is a hard ERROR —
    // it silently publishes the forward on every interface.
    let bad = r#"
        version = 1
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [[profiles.forwards]]
        name = "f"
        type = "local"
        transport = "tcp"
        bind = "0.0.0.0:8080"
        target = "127.0.0.1:80"
    "#;
    assert!(
        has_error(bad, "wildcard_bind_without_expose"),
        "wildcard bind gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: same bind with the explicit acknowledgement.
    let ok = r#"
        version = 1
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [[profiles.forwards]]
        name = "f"
        type = "local"
        transport = "tcp"
        bind = "0.0.0.0:8080"
        target = "127.0.0.1:80"
        expose = true
    "#;
    assert!(!has_error(ok, "wildcard_bind_without_expose"));
}

#[test]
fn non_loopback_bind_without_expose_fires_and_clears() {
    // FIRE (WARNING): a routable, non-loopback bind without `expose`.
    let bad = r#"
        version = 1
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [[profiles.forwards]]
        name = "f"
        type = "local"
        transport = "tcp"
        bind = "192.0.2.10:8080"
        target = "127.0.0.1:80"
    "#;
    assert!(
        has_warning(bad, "non_loopback_bind_without_expose"),
        "non-loopback bind gate must warn: {:?}",
        diags(bad).warnings
    );

    // NO-FIRE: acknowledged with `expose = true`.
    let ok = r#"
        version = 1
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [[profiles.forwards]]
        name = "f"
        type = "local"
        transport = "tcp"
        bind = "192.0.2.10:8080"
        target = "127.0.0.1:80"
        expose = true
    "#;
    assert!(!has_warning(ok, "non_loopback_bind_without_expose"));
}

#[test]
fn mcp_non_loopback_requires_expose_fires_and_clears() {
    // FIRE: an MCP listener on a non-loopback address without `expose`.
    let bad = r#"
        version = 1
        [mcp]
        listen = "192.0.2.10:7000"
    "#;
    assert!(
        has_error(bad, "mcp_non_loopback_requires_expose"),
        "mcp expose gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: acknowledged with `expose = true`.
    let ok = r#"
        version = 1
        [mcp]
        listen = "192.0.2.10:7000"
        expose = true
    "#;
    assert!(!has_error(ok, "mcp_non_loopback_requires_expose"));
}

// ---------------------------------------------------------------------------
// Status API TLS / auth gates (E6-F3)
// ---------------------------------------------------------------------------

#[test]
fn status_api_tls_missing_cert_and_key_fire_and_clear() {
    // FIRE: TLS enabled but neither cert nor key path supplied → both codes.
    let bad = r#"
        version = 1
        [status_api]
        enabled = true
        bind = "127.0.0.1:9617"
        [status_api.tls]
        enabled = true
    "#;
    assert!(
        has_error(bad, "status_api_tls_missing_cert"),
        "missing-cert gate must fire: {:?}",
        diags(bad).errors
    );
    assert!(
        has_error(bad, "status_api_tls_missing_key"),
        "missing-key gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: both material paths present.
    let ok = r#"
        version = 1
        [status_api]
        enabled = true
        bind = "127.0.0.1:9617"
        [status_api.tls]
        enabled = true
        cert_file = "/etc/spt/status.pem"
        key_file = "/etc/spt/status.key"
    "#;
    assert!(!has_error(ok, "status_api_tls_missing_cert"));
    assert!(!has_error(ok, "status_api_tls_missing_key"));
}

#[test]
fn status_api_mtls_no_subjects_fires_and_clears() {
    // FIRE: mTLS with an empty allow-list rejects every client — flagged so the
    // operator does not ship an API that trusts no one (or, worse, that a later
    // change makes trust everyone).
    let bad = r#"
        version = 1
        [status_api]
        enabled = true
        bind = "127.0.0.1:9617"
        [status_api.tls]
        enabled = true
        cert_file = "/etc/spt/status.pem"
        key_file = "/etc/spt/status.key"
        [status_api.auth]
        mode = "mtls"
        ca_bundle = "/etc/spt/clients-ca.pem"
        allowed_subjects = []
    "#;
    assert!(
        has_error(bad, "status_api_mtls_no_subjects"),
        "empty mTLS subject list must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: a concrete subject whitelist.
    let ok = r#"
        version = 1
        [status_api]
        enabled = true
        bind = "127.0.0.1:9617"
        [status_api.tls]
        enabled = true
        cert_file = "/etc/spt/status.pem"
        key_file = "/etc/spt/status.key"
        [status_api.auth]
        mode = "mtls"
        ca_bundle = "/etc/spt/clients-ca.pem"
        allowed_subjects = ["CN=prom.internal"]
    "#;
    assert!(!has_error(ok, "status_api_mtls_no_subjects"));
}

#[test]
fn status_api_credentials_plaintext_fires_and_clears() {
    // FIRE (WARNING): bearer credentials on a non-loopback bind with TLS off.
    let bad = r#"
        version = 1
        [status_api]
        enabled = true
        bind = "192.0.2.10:9617"
        [status_api.tls]
        enabled = false
        [status_api.auth]
        mode = "bearer"
        token_from = "secret://status/token"
    "#;
    assert!(
        has_warning(bad, "status_api_credentials_plaintext"),
        "plaintext-credentials gate must warn: {:?}",
        diags(bad).warnings
    );

    // NO-FIRE: loopback bind keeps credentials local.
    let ok = r#"
        version = 1
        [status_api]
        enabled = true
        bind = "127.0.0.1:9617"
        [status_api.tls]
        enabled = false
        [status_api.auth]
        mode = "bearer"
        token_from = "secret://status/token"
    "#;
    assert!(!has_warning(ok, "status_api_credentials_plaintext"));
}

// ---------------------------------------------------------------------------
// Remote-config pull integrity gates (spec §14.3)
// ---------------------------------------------------------------------------

#[test]
fn remote_config_missing_url_fires_and_clears() {
    // FIRE: remote-config enabled with no URL.
    let bad = r"
        version = 1
        [runtime.remote_config]
        enabled = true
    ";
    assert!(
        has_error(bad, "remote_config_missing_url"),
        "missing-url gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: URL supplied (HTTPS + pin so no other remote-config code fires).
    let ok = r#"
        version = 1
        [runtime.remote_config]
        enabled = true
        url = "https://cfg.example.com/spt.toml"
        fingerprint_sha256 = "aa"
    "#;
    assert!(!has_error(ok, "remote_config_missing_url"));
}

#[test]
fn remote_config_not_https_fires_and_clears() {
    // FIRE: a plaintext-HTTP config source is a MITM handoff point.
    let bad = r#"
        version = 1
        [runtime.remote_config]
        enabled = true
        url = "http://cfg.example.com/spt.toml"
        fingerprint_sha256 = "aa"
    "#;
    assert!(
        has_error(bad, "remote_config_not_https"),
        "non-HTTPS remote config must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: HTTPS URL.
    let ok = r#"
        version = 1
        [runtime.remote_config]
        enabled = true
        url = "https://cfg.example.com/spt.toml"
        fingerprint_sha256 = "aa"
    "#;
    assert!(!has_error(ok, "remote_config_not_https"));
}

#[test]
fn remote_config_no_pin_fires_and_clears() {
    // FIRE (WARNING): no fingerprint pin — the unattended pull will be refused,
    // and an operator who never sees runtime logs would otherwise be surprised.
    let bad = r#"
        version = 1
        [runtime.remote_config]
        enabled = true
        url = "https://cfg.example.com/spt.toml"
    "#;
    assert!(
        has_warning(bad, "remote_config_no_pin"),
        "missing-pin gate must warn: {:?}",
        diags(bad).warnings
    );

    // NO-FIRE: pin present.
    let ok = r#"
        version = 1
        [runtime.remote_config]
        enabled = true
        url = "https://cfg.example.com/spt.toml"
        fingerprint_sha256 = "aa"
    "#;
    assert!(!has_warning(ok, "remote_config_no_pin"));
}

// ---------------------------------------------------------------------------
// Updater source integrity gates
// ---------------------------------------------------------------------------

#[test]
fn updater_url_required_fires_and_clears() {
    // FIRE: `source = "url"` with no URL.
    let bad = r#"
        version = 1
        [updater]
        source = "url"
    "#;
    assert!(
        has_error(bad, "updater_url_required"),
        "updater url-required gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: url + fingerprint present.
    let ok = r#"
        version = 1
        [updater]
        source = "url"
        url = "https://releases.example.com/manifest.json"
        url_fingerprint = "deadbeef"
    "#;
    assert!(!has_error(ok, "updater_url_required"));
}

#[test]
fn updater_unknown_source_fires_and_clears() {
    // FIRE: an unrecognised updater source string.
    let bad = r#"
        version = 1
        [updater]
        source = "ftp"
    "#;
    assert!(
        has_error(bad, "updater_unknown_source"),
        "unknown-source gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: a documented source.
    let ok = r#"
        version = 1
        [updater]
        source = "github"
    "#;
    assert!(!has_error(ok, "updater_unknown_source"));
}

#[test]
fn updater_static_dir_required_fires_and_clears() {
    // FIRE: `source = "static"` with no directory.
    let bad = r#"
        version = 1
        [updater]
        source = "static"
    "#;
    assert!(
        has_error(bad, "updater_static_dir_required"),
        "static-dir-required gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: static_dir supplied.
    let ok = r#"
        version = 1
        [updater]
        source = "static"
        static_dir = "/var/lib/spt/updates"
    "#;
    assert!(!has_error(ok, "updater_static_dir_required"));
}

// ---------------------------------------------------------------------------
// Remote-log (syslog TLS) client-auth gate
// ---------------------------------------------------------------------------

#[test]
fn syslog_tls_client_auth_incomplete_fires_and_clears() {
    // FIRE: a client cert with no matching key (or vice-versa) can never mount
    // mTLS to the log sink.
    let bad = r#"
        version = 1
        [logging]
        [[logging.remote]]
        name = "tls"
        type = "syslog_tls"
        endpoint = "logs.example.com:6514"
        server_name = "logs.example.com"
        client_cert = "/etc/spt/log-client.pem"
    "#;
    assert!(
        has_error(bad, "syslog_tls_client_auth_incomplete"),
        "incomplete client-auth gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: cert + key configured together.
    let ok = r#"
        version = 1
        [logging]
        [[logging.remote]]
        name = "tls"
        type = "syslog_tls"
        endpoint = "logs.example.com:6514"
        server_name = "logs.example.com"
        client_cert = "/etc/spt/log-client.pem"
        client_key = "/etc/spt/log-client.key"
    "#;
    assert!(!has_error(ok, "syslog_tls_client_auth_incomplete"));
}

// ---------------------------------------------------------------------------
// Protocol-gate diagnostics (`*_requires_ssh2`)
// ---------------------------------------------------------------------------

/// SSH3 profile header shared by the `*_requires_ssh2` fire cases.
const SSH3_HEADER: &str = r#"
    [[profiles]]
    name = "p"
    protocol = "ssh3"
    endpoint = "https://h:443/ssh3?user={username}"
    acknowledge_experimental = true
"#;

#[test]
fn gssapi_requires_ssh2_fires_and_clears() {
    // FIRE: GSSAPI auth on a non-ssh2 (ssh3) profile.
    let bad = format!(
        r#"
        version = 1
        [capabilities]
        allow_gssapi = true
        {SSH3_HEADER}
        [profiles.auth]
        method = "gssapi"
    "#
    );
    assert!(
        has_error(&bad, "gssapi_requires_ssh2"),
        "gssapi ssh2-gate must fire: {:?}",
        diags(&bad).errors
    );

    // NO-FIRE: GSSAPI on an ssh2 profile with the capability enabled.
    let ok = r#"
        version = 1
        [capabilities]
        allow_gssapi = true
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [profiles.auth]
        method = "gssapi"
    "#;
    assert!(!has_error(ok, "gssapi_requires_ssh2"));
}

#[test]
fn sspi_requires_ssh2_fires_and_clears() {
    // FIRE: SSPI auth on an ssh3 profile.
    let bad = format!(
        r#"
        version = 1
        [capabilities]
        allow_sspi = true
        {SSH3_HEADER}
        [profiles.auth]
        method = "sspi"
    "#
    );
    assert!(
        has_error(&bad, "sspi_requires_ssh2"),
        "sspi ssh2-gate must fire: {:?}",
        diags(&bad).errors
    );

    // NO-FIRE: SSPI on an ssh2 profile with the capability enabled.
    let ok = r#"
        version = 1
        [capabilities]
        allow_sspi = true
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [profiles.auth]
        method = "sspi"
    "#;
    assert!(!has_error(ok, "sspi_requires_ssh2"));
}

#[test]
fn post_quantum_kex_requires_ssh2_fires_and_clears() {
    // FIRE: PQ KEX configured on an ssh3 profile (SSH KEX is an ssh2 concept).
    let bad = format!(
        r#"
        version = 1
        [capabilities]
        allow_post_quantum_kex = true
        {SSH3_HEADER}
        [profiles.crypto]
        kex_algorithms = ["sntrup761x25519-sha512"]
    "#
    );
    assert!(
        has_error(&bad, "post_quantum_kex_requires_ssh2"),
        "PQ-KEX ssh2-gate must fire: {:?}",
        diags(&bad).errors
    );

    // NO-FIRE: same KEX on an ssh2 profile with the capability enabled.
    let ok = r#"
        version = 1
        [capabilities]
        allow_post_quantum_kex = true
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [profiles.crypto]
        kex_algorithms = ["sntrup761x25519-sha512"]
    "#;
    assert!(!has_error(ok, "post_quantum_kex_requires_ssh2"));
}

#[test]
fn sftp_mount_requires_ssh2_fires_and_clears() {
    // FIRE: an SFTP mount on an ssh3 profile (SFTP rides an ssh2 subsystem).
    let bad = format!(
        r#"
        version = 1
        [capabilities]
        allow_sftp = true
        allow_filesystem_mounts = true
        {SSH3_HEADER}
        [[profiles.sftp_mounts]]
        name = "data"
        remote_path = "/srv/data"
        mount_point = "/mnt/data"
    "#
    );
    assert!(
        has_error(&bad, "sftp_mount_requires_ssh2"),
        "sftp ssh2-gate must fire: {:?}",
        diags(&bad).errors
    );

    // NO-FIRE: the same mount on an ssh2 profile with capabilities enabled.
    let ok = r#"
        version = 1
        [capabilities]
        allow_sftp = true
        allow_filesystem_mounts = true
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [[profiles.sftp_mounts]]
        name = "data"
        remote_path = "/srv/data"
        mount_point = "/mnt/data"
    "#;
    assert!(!has_error(ok, "sftp_mount_requires_ssh2"));
}

#[test]
fn dynamic_forward_requires_ssh2_fires_and_clears() {
    // FIRE: a dynamic (SOCKS) forward on an ssh3 profile.
    let bad = format!(
        r#"
        version = 1
        [capabilities]
        allow_dynamic_proxy = true
        {SSH3_HEADER}
        [[profiles.forwards]]
        name = "proxy"
        type = "dynamic"
        transport = "tcp"
        bind = "127.0.0.1:1080"
    "#
    );
    assert!(
        has_error(&bad, "dynamic_forward_requires_ssh2"),
        "dynamic-forward ssh2-gate must fire: {:?}",
        diags(&bad).errors
    );

    // NO-FIRE: dynamic forward on an ssh2 profile with the capability enabled.
    let ok = r#"
        version = 1
        [capabilities]
        allow_dynamic_proxy = true
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [[profiles.forwards]]
        name = "proxy"
        type = "dynamic"
        transport = "tcp"
        bind = "127.0.0.1:1080"
    "#;
    assert!(!has_error(ok, "dynamic_forward_requires_ssh2"));
}

// ---------------------------------------------------------------------------
// Capability fail-closed gates (auth methods / delegation / cache)
// ---------------------------------------------------------------------------

#[test]
fn sspi_capability_disabled_fires_and_clears() {
    // FIRE: SSPI auth without `capabilities.allow_sspi = true`.
    let bad = r#"
        version = 1
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [profiles.auth]
        method = "sspi"
    "#;
    assert!(
        has_error(bad, "sspi_capability_disabled"),
        "sspi capability gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: capability enabled.
    let ok = r#"
        version = 1
        [capabilities]
        allow_sspi = true
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [profiles.auth]
        method = "sspi"
    "#;
    assert!(!has_error(ok, "sspi_capability_disabled"));
}

#[test]
fn gssapi_delegation_capability_disabled_fires_and_clears() {
    // FIRE: credential delegation requested without the delegation capability.
    let bad = r#"
        version = 1
        [capabilities]
        allow_gssapi = true
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [profiles.auth]
        method = "gssapi"
        gssapi_delegate = true
    "#;
    assert!(
        has_error(bad, "gssapi_delegation_capability_disabled"),
        "gssapi delegation gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: delegation capability granted alongside the provider.
    let ok = r#"
        version = 1
        [capabilities]
        allow_gssapi = true
        allow_gssapi_delegation = true
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [profiles.auth]
        method = "gssapi"
        gssapi_delegate = true
    "#;
    assert!(!has_error(ok, "gssapi_delegation_capability_disabled"));
}

#[test]
fn sspi_delegation_capability_disabled_fires_and_clears() {
    // FIRE: SSPI delegation requested without the delegation capability.
    let bad = r#"
        version = 1
        [capabilities]
        allow_sspi = true
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [profiles.auth]
        method = "sspi"
        sspi_delegate = true
    "#;
    assert!(
        has_error(bad, "sspi_delegation_capability_disabled"),
        "sspi delegation gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: delegation capability granted alongside the provider.
    let ok = r#"
        version = 1
        [capabilities]
        allow_sspi = true
        allow_gssapi_delegation = true
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [profiles.auth]
        method = "sspi"
        sspi_delegate = true
    "#;
    assert!(!has_error(ok, "sspi_delegation_capability_disabled"));
}

#[test]
fn sftp_writeback_capability_disabled_fires_and_clears() {
    // FIRE: a writeback cache without `capabilities.allow_writeback_cache`
    // silently loses buffered writes on crash — gated as an ERROR.
    let bad = r#"
        version = 1
        [capabilities]
        allow_sftp = true
        allow_filesystem_mounts = true
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [[profiles.sftp_mounts]]
        name = "data"
        remote_path = "/srv/data"
        mount_point = "/mnt/data"
        cache = "writeback"
    "#;
    assert!(
        has_error(bad, "sftp_writeback_capability_disabled"),
        "writeback capability gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: writeback capability granted.
    let ok = r#"
        version = 1
        [capabilities]
        allow_sftp = true
        allow_filesystem_mounts = true
        allow_writeback_cache = true
        [[profiles]]
        name = "p"
        protocol = "ssh2"
        host = "h"
        [[profiles.sftp_mounts]]
        name = "data"
        remote_path = "/srv/data"
        mount_point = "/mnt/data"
        cache = "writeback"
    "#;
    assert!(!has_error(ok, "sftp_writeback_capability_disabled"));
}

#[test]
fn capabilities_ml_kem_without_pq_fires_and_clears() {
    // FIRE (WARNING): ML-KEM allowed but the PQ-KEX master switch is off, so the
    // ML-KEM allowance is inert — surfaced so an operator is not misled.
    let bad = r"
        version = 1
        [capabilities]
        allow_ml_kem = true
    ";
    assert!(
        has_warning(bad, "capabilities_ml_kem_without_pq"),
        "ml-kem-without-pq honesty gate must warn: {:?}",
        diags(bad).warnings
    );

    // NO-FIRE: PQ-KEX also enabled.
    let ok = r"
        version = 1
        [capabilities]
        allow_ml_kem = true
        allow_post_quantum_kex = true
    ";
    assert!(!has_warning(ok, "capabilities_ml_kem_without_pq"));
}

// ---------------------------------------------------------------------------
// SNMP USM secret-required gates
// ---------------------------------------------------------------------------

#[test]
fn snmp_user_auth_secret_required_fires_and_clears() {
    // FIRE: an auth protocol declared with no auth secret — the USM user would
    // silently fall back to noAuthNoPriv.
    let bad = r#"
        version = 1
        [observability.snmp]
        [[observability.snmp.users]]
        name = "monitor"
        auth_protocol = "hmac_sha256"
    "#;
    assert!(
        has_error(bad, "snmp_user_auth_secret_required"),
        "snmp auth-secret gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: auth secret supplied.
    let ok = r#"
        version = 1
        [observability.snmp]
        [[observability.snmp.users]]
        name = "monitor"
        auth_protocol = "hmac_sha256"
        auth_secret = "secret://snmp/auth"
    "#;
    assert!(!has_error(ok, "snmp_user_auth_secret_required"));
}

#[test]
fn snmp_user_priv_secret_required_fires_and_clears() {
    // FIRE: a privacy protocol declared with no privacy secret — the USM user
    // would silently drop to authNoPriv (unencrypted).
    let bad = r#"
        version = 1
        [observability.snmp]
        [[observability.snmp.users]]
        name = "monitor"
        auth_protocol = "hmac_sha256"
        auth_secret = "secret://snmp/auth"
        priv_protocol = "aes128"
    "#;
    assert!(
        has_error(bad, "snmp_user_priv_secret_required"),
        "snmp privacy-secret gate must fire: {:?}",
        diags(bad).errors
    );

    // NO-FIRE: privacy secret supplied.
    let ok = r#"
        version = 1
        [observability.snmp]
        [[observability.snmp.users]]
        name = "monitor"
        auth_protocol = "hmac_sha256"
        auth_secret = "secret://snmp/auth"
        priv_protocol = "aes128"
        privacy_secret = "secret://snmp/priv"
    "#;
    assert!(!has_error(ok, "snmp_user_priv_secret_required"));
}
