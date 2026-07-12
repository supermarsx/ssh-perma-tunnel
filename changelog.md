## [26.57] - 2026-07-12

# spt 26.57

## Changes since 26.56

- ci: keep standalone lockfiles aligned on release (841f242)

## [26.56] - 2026-07-12

# spt 26.56

## Changes since 26.55

- test: relax loaded ssh2 dataplane timeout (fe51231)
- test: avoid fixed ftp passive ports (79133e3)
- chore: refresh standalone test lockfiles (53480db)

## [26.55] - 2026-07-11

# spt 26.55

## Changes since 26.54

- docs: improve readme onboarding (3dcc72d)
- chore: add target cleanup scripts (326de12)

## [26.54] - 2026-07-11

# spt 26.54

## Changes since 26.53

- fix ssh3 uds ci tests (82aa4f5)
- chore(tests): refresh standalone lockfiles (2def71a)
- fix(cli): publish SSH3 auth-file completions (19b95c2)
- docs(trust): mark WebPKI as code in CRL docs (c8f335e)
- fix(ssh2): restore host-key verification test stability (1505878)
- fix(ssh3): use configured signature algorithms for pinned TLS (71829e2)
- fix(ssh3): pass UDS authorizers in forwarding tests (e6fda6a)
- Merge pull request #72 from supermarsx/smx/propose-fix-for-sftp-security-vulnerability-2026-07-11 (706826b)
- Prevent HKCU policy from enabling SFTP (cc12225)
- Merge pull request #56 from supermarsx/smx/fix-known_hosts-index-bypass-vulnerability-2026-07-10 (5c00e1f)
- Merge pull request #58 from supermarsx/smx/fix-unsigned-crls-trusted-in-tls-2026-07-10 (43c7e92)
- Merge pull request #59 from supermarsx/smx/propose-fix-for-auth-tls-vulnerability-2026-07-10 (55b97c6)
- Merge pull request #63 from supermarsx/smx/fix-pin-only-tls-certificate-verification-vulnerability-2026-07-10 (36edf52)
- Merge pull request #60 from supermarsx/smx/propose-fix-for-sftp-cli-vulnerability-2026-07-10 (bf7f304)
- Merge pull request #64 from supermarsx/smx/fix-bracketed-bareword-secrets-leak-2026-07-10 (1e200c1)
- Merge pull request #65 from supermarsx/smx/fix-bind_mode-bypassing-expose-validation-2026-07-10 (ef8a391)
- Merge pull request #66 from supermarsx/smx/fix-unvalidated-network-bind-parameters-2026-07-10 (dfebf2e)
- Merge pull request #61 from supermarsx/smx/fix-denial-of-service-vulnerability-2026-07-10 (e56990f)
- Merge pull request #67 from supermarsx/smx/fix-ssh3-remote-udp-forwarding-vulnerability-2026-07-10 (d3a3917)
- Merge pull request #68 from supermarsx/smx/fix-oidc-device-flow-vulnerability-2026-07-10 (28ae301)
- Merge pull request #71 from supermarsx/smx/propose-fix-for-wix-download-vulnerability-2026-07-10 (1786da2)
- ci: verify cached WiX archive integrity (2f10e53)
- Merge pull request #70 from supermarsx/smx/fix-unpinned-prebuilt-packaging-tools-2026-07-10 (e33cd59)
- ci: pin Linux packaging tool installs (bf2a014)
- Merge pull request #69 from supermarsx/smx/propose-fix-for-ssh-hop-trust-issue-2026-07-10 (96f584d)
- fix(ssh2): preserve hop trust hostname (f6fcc61)
- Validate OIDC discovery metadata (169ec74)
- fix(config): enforce network interface bind policy (ea71564)
- Fix SSH3 remote UDP peer hijack (c6e87bd)
- fix: require expose for broad bind modes (16376f9)
- Fix bracketed bareword secret redaction (d79463f)
- Verify TLS signatures in pin-only connector (35d47c2)
- Bound dynamic proxy handshakes (47d1885)
- Apply policy overlay to SFTP config loads (5ee2ff7)
- Bound FTP TLS handshakes (11d44fe)
- Validate CRL authority before revocation lookup (6191baf)
- fix: preserve known_hosts revocation precedence (66f8029)
- Merge pull request #53 from supermarsx/smx/propose-fix-for-ssh-host-key-vulnerability-2026-07-09 (d7c5f3b)
- Merge branch 'main' into smx/propose-fix-for-ssh-host-key-vulnerability-2026-07-09 (979a7c5)
- Merge pull request #55 from supermarsx/smx/fix-smtp-event-sinks-tls-spki-pinning-issue-2026-07-10 (cc4a1e0)
- Merge pull request #54 from supermarsx/smx/fix-ssh3-serve-open-relay-vulnerability-2026-07-10 (94dd2d8)
- Merge branch 'main' into smx/fix-ssh3-serve-open-relay-vulnerability-2026-07-10 (93e13b2)
- fix: fail closed on pinned SMTP event sinks (212d4a4)
- fix: fail closed for ssh3 serve exposure (b8b4e8c)
- fix(security): fail closed on TOFU persistence errors (6f0b4e1)
- Merge pull request #52 from supermarsx/smx/fix-ssh3-pin-only-tls-vulnerability-2026-07-09 (49b864f)
- Merge branch 'main' into smx/fix-ssh3-pin-only-tls-vulnerability-2026-07-09 (8ae1562)
- fix(ssh3): verify TLS signatures without chain verifier (df0f72c)
- Merge pull request #51 from supermarsx/smx/fix-ssh3-uds-target-acl-vulnerability-2026-07-09 (b857edf)
- fix: enforce SSH3 UDS path ACL (50e0523)
- Merge pull request #50 from supermarsx/smx/fix-socks-target-acl-validation-flaw-2026-07-09 (fae2c33)
- fix: normalize numeric IPv4 ACL targets (5cb1f11)
- Merge pull request #49 from supermarsx/smx/fix-tofu-known_hosts-vulnerability-2026-07-09 (6f134d5)
- fix(ssh2): serialize TOFU known_hosts rewrites (7ce5ebe)
- Merge pull request #48 from supermarsx/smx/fix-ssh3-pin-only-tls-vulnerability-2026-07-09 (dd7c0c4)
- fix ssh3 pin-only certificate signatures (81b72d9)
- Merge pull request #47 from supermarsx/smx/propose-fix-for-firewall-runtime-vulnerability-2026-07-09 (e6086f6)
- fix(firewall): skip remote forwards in local rules (4259583)
- Merge pull request #46 from supermarsx/smx/fix-ssh3-recipe-token-leak-2026-07-09 (aebce54)
- fix: avoid SSH3 recipe argv secret leak (1196ec2)

## [26.53] - 2026-07-08

# spt 26.53

## Changes since 26.52

- chore: resync chaos + property locks to 0.26.52 (7d7f658)

## [26.52] - 2026-07-08

# spt 26.52

## Changes since 26.51

- chore: remove accidentally-committed redirect artifacts; gitignore them (1059f74)
- fix(tls): standardize on a single rustls provider (aws-lc-rs) — unbreak CI (308829d)
- feat(net): enforce [network.gateway] as a fail-closed runtime guard (a3ce913)
- feat: enforce forward.max_datagram_size; add ssh3 post_quantum TOML off-switch (24badb7)
- feat(ssh3): post-quantum X25519MLKEM768 KEX by default (+ Windows stdout fix) (2219b4f)

## [26.51] - 2026-07-07

# spt 26.51

## Changes since 26.50

- feat: negotiated-crypto observability, supply-chain gate, opt-in native build (be2ab31)

## [26.50] - 2026-07-06

# spt 26.50

## Changes since 26.49

- feat(ssh2): offer post-quantum ML-KEM KEX by default (e628168)
- docs(architecture): clean up the layered-overview diagram (4ba4b9f)
- docs: add tool comparison, use-cases/recipes, development guide; deepen architecture (cb5a216)
- ci(docs): upgrade Pages actions to latest (clears last Node 20 runtime) (828062a)

## [26.49] - 2026-07-03

# spt 26.49

## Changes since 26.48

- chore: resync chaos + property locks to 0.26.48 (09e3d6f)

## [26.48] - 2026-07-03

# spt 26.48

## Changes since 26.47

- fix(ci): gate macOS-fragile 4mib dataplane harness test; grant docs Pages write (ab3e265)
- test: across-board regression suite (auth/trust, updater, validate, firewall, lifecycle) (a16a999)
- test(dataplane): extensive matrix-driven regression suite across all transports (767f2aa)
- chore: resync chaos + property locks to 0.26.47 (4b75c14)
- ci+docs: upgrade GitHub Actions to latest + add extensive mdBook GitHub Pages docs (17c1b65)

## [26.47] - 2026-07-03

# spt 26.47

## Changes since 26.46

- chore: resync chaos + property sub-workspace locks to 0.26.46 (51493a4)
- fix(dataplane): hardcore-review remediation — obfs desync, meek, idle-watchdog, ssh3 UDP, shutdown race (9e9d552)

## [26.46] - 2026-07-03

# spt 26.46

## Changes since 26.45

- fix(ci): backtick it_completion in help_snapshots doc (clippy::doc_markdown) (d789174)
- fix(ci): skip default-surface help snapshots under --all-features (0882c8b)
- fix(review): ultra-hardcore remediation — TUI input bug + editability, zeroize, honesty, fuzz, all-features CI (5b04026)

## [26.45] - 2026-07-03

# spt 26.45

## Changes since 26.44

- fix(wiring): Wave 9 — global cleanup (all-features clippy, LF normalization, spt-benchmark) (31c5d97)
- chore: enforce LF in working tree via .gitattributes eol=lf (6999572)
- fix(wiring): Wave 8 — honesty sweep (schema + validate warns + supervisor logging + TUI + config-set) (7a3c515)
- fix(wiring): Wave 7 — metrics toggle + config-reload watcher + diagnostics + benchmark caps (dcc858f)
- fix(wiring): Wave 6 — firewall runtime application + network offload → TcpOptions (a9d11af)
- fix(snmp): self dev-dep so USM-logging test runs under default CI features (c2c04ea)
- fix(wiring): Wave 5 — SNMP serving wired end-to-end (Critical dead subsystem) (e273db9)
- fix(wiring): Wave 4 — event sinks + updater + DNS hosts_file + MCP, with verify/deny logging (67af880)

## [26.44] - 2026-07-03

# spt 26.44

## Changes since 26.43

- fix(wiring): Wave 3 — transport/forward limit enforcement + host-key-mismatch logging (359bc4a)
- chore(completions): regenerate for Wave-2 `service install` flags (72201d0)
- fix(wiring): Wave 2 — security TLS + secrets(vault/mlock) + service-install + OOM P2/P3 (cbf923b)

## [26.43] - 2026-07-02

# spt 26.43

## Changes since 26.42

- fix(wiring): Wave 1 — dangerous CLI + SFTP safety + OOM P1 + 3 leaks (dcf1356)

## [26.42] - 2026-07-02

# spt 26.42

## Changes since 26.41

- harden(docker): resource limits for exhaustion/leak/compromise safety (e86e11c)

## [26.41] - 2026-07-02

# spt 26.41

## Changes since 26.40

- fix(docker): config/secrets/state mounts + graceful-shutdown alignment for containers (81dce0f)

## [26.40] - 2026-07-02

# spt 26.40

## Changes since 26.39

- fix(resilience): self-healing/persistence/lifecycle hardening (ultra review) (52dc470)

## [26.39] - 2026-07-02

# spt 26.39

## Changes since 26.38

- chore(deps): bump anyhow 1.0.103 + crypto-bigint 0.7.5 (clear audit warnings) (ec4aa3e)

## [26.38] - 2026-07-01

# spt 26.38

## Changes since 26.37

- fix(security): hardcore round-2 — reverse-forward DoS cap, unit-file & ACL hardening, TOTP overflow, + test-integrity (keychain flake, vacuous redaction tests) (9294998)

## [26.37] - 2026-06-30

# spt 26.37

## Changes since 26.36

- fix(ci): macOS sshfs umount compile error + property sub-workspace lock sync (98026a1)
- fix(security): ultra-review wave 3 — Windows file ACLs, lifecycle/DoS, obfs perf, + rescue false-green security tests (b601aba)

## [26.36] - 2026-06-30

# spt 26.36

## Changes since 26.35

- fix(security): ultra-review wave 2 — MCP secret leak, FTP, events injection, SecretRef traversal (76b406c)

## [26.35] - 2026-06-30

# spt 26.35

## Changes since 26.34

- fix(security): SNMP USM auth-bypass (Critical) + ultra-review regression fixes (11eae8d)

## [26.34] - 2026-06-30

# spt 26.34

## Changes since 26.33

- fix: hardcore review — ssh3 leak (Critical), supervisor/correctness, DoS, crypto, injection (30a86ed)

## [26.33] - 2026-06-29

# spt 26.33

## Changes since 26.32

- chore(security): dep RUSTSEC fixes, SOCKS target ACL, secret zeroization, hardened Docker (ad39c14)

## [26.32] - 2026-06-25

# spt 26.32

## Changes since 26.31

- test: extensive coverage for high-risk under-tested modules (~179 tests) (e558f4e)

## [26.31] - 2026-06-25

# spt 26.31

## Changes since 26.30

- fix(security): batch 3 — overflow-checks on release, decoder fuzz harnesses, key chmod (f96a903)

## [26.30] - 2026-06-25

# spt 26.30

## Changes since 26.29

- chore: remove stray crates/spt-tui/<memory> artifact (9a92823)

## [26.29] - 2026-06-25

# spt 26.29

## Changes since 26.28

- fix(security): batch 2 — offensive deep-dive fixes (DoS, injection, authenticity) (4da81ce)

## [26.28] - 2026-06-25

# spt 26.28

## Changes since 26.27

- fix(security): batch 1 — quinn CVE bump + SNMP/updater/SFTP/firewall hardening (b065326)

## [26.27] - 2026-06-25

# spt 26.27

## Changes since 26.26

- fix(test): shorten ssh3 UDS socket paths (macOS sun_path limit, flaky aarch64-darwin) (79656d1)
- fix(ssh2): resolve the shadowsocks obfuscation password SecretRef before dialing (7448e22)
- fix(e2e): clear clippy lints in the new e2e tests (CI was red) (d1a6ab3)
- test(e2e): broaden end-to-end coverage (~46 tests) + spt-updater test mock (42dbae1)

## [26.26] - 2026-06-24

# spt 26.26

## Changes since 26.25

- chore: remove tracked clippy files (clippy.toml + stray artifact) (1cc90de)
- test(e2e): config-crypt tunnel-up end-to-end (PSK + X25519) (c09e29f)

## [26.25] - 2026-06-24

# spt 26.25

## Changes since 26.24

- feat(config-crypt): raw-PSK AES mode, key generation, and remote-config decrypt-on-fetch (903a524)

## [26.24] - 2026-06-24

# spt 26.24

## Changes since 26.23

- fix(secrets): keychain unavailability falls through instead of aborting the resolver chain (7c5b5c5)
- feat: implement pending in-code TODOs (updater + CLI phase-B + event sinks) (8f45de0)

## [26.23] - 2026-06-23

# spt 26.23

## Changes since 26.22

- feat(ssh3): UDS (unix-socket) forwarding over the ssh3 transport (77ce6bb)

## [26.22] - 2026-06-23

# spt 26.22

## Changes since 26.21

- feat(dns): wire profile.dns_resolution=once and forward/hop target_resolve=local (8a8b23a)

## [26.21] - 2026-06-23

# spt 26.21

## Changes since 26.20

- feat(ssh3): add `spt ssh3-serve` subcommand (the spt<->spt server end) (3d820c1)

## [26.20] - 2026-06-23

# spt 26.20

## Changes since 26.19

- feat(ssh3): make the SSH3 (QUIC/TLS/HTTP3) transport fully live (5e18589)

## [26.19] - 2026-06-23

# spt 26.19

## Changes since 26.18

- style: cargo fmt the round-2 wiring (runner/russh_backend/instability) (6a1cc5a)
- feat(profile): wire remaining deferred tunnel fields (timeouts, remote-UDS, auth-preflight, latency-instability) (d152576)

## [26.18] - 2026-06-22

# spt 26.18

## Changes since 26.17

- feat(profile): wire [profiles.connection] socket + channel knobs (04b1bf5)

## [26.17] - 2026-06-22

# spt 26.17

## Changes since 26.16

- fix(chaos): add BackoffConfig.retry_auth_failures field after tunnel-field wiring (7526700)
- feat: wire dead tunnel config fields so they actually take effect + ~75 coverage tests (f57c907)

## [26.16] - 2026-06-19

# spt 26.16

## Changes since 26.15

- fix(ci): regenerate tests/chaos/Cargo.lock after t-memleak dev-dep edges (d3d6c2b)
- feat: memory-leak detection (events) + extensive leak tests + events fully configurable (b38b8c7)

## [26.15] - 2026-06-18

# spt 26.15

## Changes since 26.14

- feat(cli): colorize human readouts + show real service status in `spt status` (d9734f4)

## [26.14] - 2026-06-18

# spt 26.14

## Changes since 26.13

- feat(cli): repurpose `spt status` as app overview; move API controls to `spt status-api` (0671994)

## [26.13] - 2026-06-17

# spt 26.13

## Changes since 26.12

- feat(mcp): events_subscribe streaming + chore: accept rsa Marvin advisory (no upstream fix) (0044011)

## [26.12] - 2026-06-17

# spt 26.12

## Changes since 26.11

- fix(test): firewall_apply_with_yes asserts routing, not privileged mutation success (3720510)
- feat: wire remaining capabilities (event sinks, live bench, DNS runtime, e2e, sd_notify, firewall --yes) (5bc3f28)

## [26.11] - 2026-06-13

# spt 26.11

## Changes since 26.10

- fix(ci): regenerate tests/chaos/Cargo.lock after spt-key rsa dep (f41134f)
- fix(spt-key): correct RSA cert-signing; chore: dependabot MSRV 1.83->1.88 (bda276c)

## [26.10] - 2026-06-13

# spt 26.10

## Changes since 26.9

- fix(ci): rustfmt, cfg(unix) clippy lints, and chaos lockfile after 1.88/russh modernization (c478686)
- chore: MSRV 1.85->1.88, modernize russh/hickory/time, + email subject & remote-config poller (98d6d21)
- feat: implement full review gap-fill + TUI-configurable DNS, events, and per-endpoint auth (e7be629)

## [26.9] - 2026-06-09

# spt 26.9

## Changes since 26.8

- fix(tui): pane-nav with Left/Right on Endpoints & Forwards two-pane pages (803df87)
- refactor(tui): delete Connection page, migrate fields to Auth + Timings & Keepalive (dacd858)
- Merge branch 'main' of https://github.com/supermarsx/ssh-perma-tunnel (1ce4c45)
- feat(tui): per-option dynamic help in the field-info footer (666e11e)

## [26.8] - 2026-06-08

# spt 26.8

## Changes since 26.7

- feat(tui): nav-mode focus highlight + ssh3 display label (`francoismichel`) (d05eff5)
- Merge branch 'main' of https://github.com/supermarsx/ssh-perma-tunnel (87264b1)
- fix(tui): cursor rotation no longer marks model dirty; add 3+ option cycle tests (8e5c93d)
- feat(tui): add dedicated Endpoints page for [[profiles.endpoints]] list editing (c636198)

## [26.7] - 2026-06-03

# spt 26.7

## Changes since 26.6

- feat(tui): syntax-highlight the Review TOML preview (761d661)
- fix(tui): make Review page scrollable with arrows / jk / PgUp / PgDn / Home / End (94b05b3)
- fix(tui): scroll tab bar so the active page is always visible (4a8a5e4)
- docs(tui): document Space/`t` as tickbox toggles in help overlay + status + docs/tui.md (fb1c532)
- fix(tui): MultiSelect tickboxes also lock to Space/`t` — Enter now commits (016ee78)
- fix(tui): Toggle accepts only Space and `t`; lock down with key matrix (c63f1a6)
- test(tui): 13 App-level end-to-end tests covering every TUI fix shipped today (43fa892)
- fix(tui): Enter on Bool commits without flipping; add `t` toggle key (8a0115e)
- fix(tui): compact spinner render for Select/MultiSelect in small areas (b8e25db)
- style(tui): collapse 4-line if-condition to satisfy rustfmt (2778e8d)
- fix(tui): show visible REVERSED caret cell on focused text fields (cd12ff1)
- fix(tui): rotate Select/MultiSelect with Left/Right and wrap at boundaries (4f3baf9)
- fix(tui): seed Select/MultiSelect cursor from current value on edit entry (4be1e58)

## [26.6] - 2026-06-01

# spt 26.6

## Changes since 26.5

- ci: WiX 3 binary cache + shared rust-cache across test+build (≈30–40min saved) (8ce6d42)
- feat(tui): `▶` selector, focused-field help footer, position counter, context-aware status (5a5f487)
- cli: scrub plan refs + "(cross-platform)" tag from help text (46aa9f4)
- fix(packaging): Windows VERSIONINFO mojibake + redundant ProductName prefix (b69a276)

## [26.5] - 2026-06-01

# spt 26.5

## Changes since 26.4

- feat(updater): supervisor spawns the embedded updater thread when enabled (48ab609)
- feat(updater): GitHub source backend + `spt update check` is now live (322ae79)
- docs(updater): operator reference + annotated example + base-config note (af38ccf)
- feat(updater): spt-updater crate skeleton + `spt update` CLI surface (6076ac5)
- feat(config): [updater] schema + load-time validation, off by default (6022cd7)
- docs: clarify SSH3 = RTH3-specific experimental, document `spt kill` (01714a8)
- ci: fix CARGO_BUILD_JOBS conditional — empty string is a parse error (f46d452)
- ci: cap rustc parallelism on aarch64-linux to avoid OOM during link (8ba29e3)
- completions: regenerate for the new `spt kill` subcommand (d41a841)
- build: embed app icon + VERSIONINFO into the binary, cross-platform-aware (e5e521c)
- feat(cli): `spt kill` — terminate every running spt instance, cross-platform (c09b96a)

## [26.4] - 2026-05-30

# spt 26.4

## Changes since 26.3

- fix(cli): `spt config init --example <name>` wires every preset (47454ee)
- ci: prepare-release job — bump Cargo.toml once, overlay everywhere (4e45711)
- test(spt-service): refresh systemd snapshots for the supermarsx URL fix (5292e0c)
- fix(tui): swallow KeyEventKind::Release / Repeat — fixes 2x key duplication on Windows (264f72b)
- manifests: typed release manifest + Cargo crates.io metadata + OCI labels (8eac04c)
- packaging: rewrite stale URLs + wire icon through MSI / snap / flathub (0407869)
- assets: canonical icon.svg + multi-format raster export tool (f0fbe17)

## [26.3] - 2026-05-29

# spt 26.3

## Changes since 26.2

- ci: refresh Cargo.lock during version bump and include it in bump commit (fc638f0)
- ci: locate Linux binaries via find rather than a hard-coded artifact path (ed1251d)

## [26.2] - 2026-05-29

# spt 26.2

## Changes since 26.1

- ci: rename dist/<old_cargo_version>/ to match the bumped version (9d29ce8)
- ci: stage Linux binaries for the Docker buildx context (fe24c86)

## [26.1] - 2026-05-29

# spt 26.1 — Release Notes

Tag: `v26.1` — first rolling release of UTC year 2026 (close-out of
milestones t6 + t7 + t8). Cargo-manifest encoding: `0.26.1` (the SemVer
prefix `0.` is required by Cargo's TOML parser; the user-facing tag and
release name drop it). See `docs/releases/readme.md` for the rolling-
release scheme and `releasing.md` for the automation.

Status: production-readiness audit closed; ship-blocking items all
resolved. See `docs/production_readiness.md` for the per-line audit
verdict.

This release lands the inaugural batch of the rolling-release stream.
Future releases will arrive on every green-CI push to `main`; tags
increment monotonically as `v26.2`, `v26.3`, ... until the UTC year
rolls over to 2027, at which point the counter resets to `v27.1`.

## Highlights

Three milestones land in this release: **t6** (feature surface complete),
**t7** (libssh2 demolished, contract stubs become real), **t8**
(production hardening).

### Post-quantum KEX (t8-B1, t8-B2, t8-B3)

`mlkem768x25519-sha256` (FIPS 203 ML-KEM-768 hybrid with X25519) lands
**live** in the vendored russh fork. Implementation matches OpenSSH
9.9's `kexmlkem768x25519.c` byte-for-byte:

* PQ component first in both wire blobs and shared-secret
  concatenation.
* `K` encoded as an SSH string (length-prefixed) in both the exchange
  hash and the RFC 4253 key-derivation iterations.
* Backed by `ml-kem 0.3.2` (RustCrypto, pure-Rust, no C deps).

`sntrup761x25519-sha512[@openssh.com]` lands **as a registered
skeleton**: both name strings appear in `ALL_KEX_ALGORITHMS` and the
wire validator parses both INIT and REPLY blob shapes, but the KEM
primitive is deferred to a follow-up rolling release pending operator
decision. See *Known
Issues* below for the three documented resume paths.

The `[profiles.crypto].kex_algorithms` validator warning lifts for
ML-KEM but is retained for SNTRUP until the KEM lands.

### Chaos engineering (t8-C1, t8-C2)

New `spt-chaos-proxy` crate: in-process TCP proxy with injectable
behaviours (`LatencyMs`, `LossPct`, `RstAfterBytes`, `Partition`,
`DnsAnswerRotation`, `HostKeyChurn`). 12 reconnect scenarios under
`tests/chaos/` validate the supervisor's full-jitter exponential
backoff (spec §11.2) against server kills, partitions, latency
spikes, RST storms, DNS flapping, host-key churn, slow-loris,
half-close, and rapid-reconnect storms.

Four scenarios are kernel-level Linux-only and gated behind
`SPT_CHAOS_FULL=1`.

### Comparative performance (t8-C3, t8-C4, t8-C5)

`spt-benchmark` gains a `Comparator` trait with `OpenSshClient` and
`AutosshClient` implementations. A 3×3×2×3 matrix (latency × loss ×
duplex × payload) — 54 cells — is checked in at
`docs/perf/baseline-v1.0.json`. A regression dashboard is published
via GitHub Pages from `bench-regression.yml`; OpenSSH 9.9 + autossh
1.4g are installed in Linux + macOS CI runners (`perf-comparators-*`
jobs).

### Diagnostics with miette spans (t8-A1, t8-A2)

Error surfacing rewritten across the top 50 error sites. `spt-core`
now exposes a `Diagnostic` carrying `what / why / how` plus `miette`-
style spans into config / wire / log payloads. FFI boundaries
(`spt-scripting`, `spt-auth-sspi`, `spt-sftp/mount/windows_winfsp`)
get explicit `catch_unwind` panic boundaries so a panic in foreign
code cannot unwind into Rust callers.

### Per-module SPT_LOG + sampling + SIGHUP / MCP reload (t8-A3)

`SPT_LOG` accepts per-module filter directives. Every span carries
`correlation_id` + `session_id`. SIGHUP and the MCP `log.set_level`
tool both apply runtime filter changes through the
`LogReloadHandle`. A `sampling` layer enforces per-target rate caps
so a noisy module cannot drown the rest of the workspace.

### 8 new fuzz targets (t8-A5)

`socks5_negotiate`, `http_connect_request`, `ftp_verb_parse`,
`ssh3_jwt_jose_header`, `openssh_config_parse`, `forward_spec_parse`,
`obfs4_frame_decode`, `shadowsocks_aead_decrypt`. PR-gating runtime
is 90 s per target. The `fuzz-dryrun` CI job dynamically discovers
targets via `cargo fuzz list`.

### Constant-time review + side-channel hardening (t8-A6)

Every secret-comparison call site audited: `spt-secrets`,
`spt-auth::totp`, `spt-key`, `spt-trust::known_hosts`. `subtle 2` is
threaded through the comparison sites. TLS pinning + cert-validation
edge cases (chain depth, expired-cert, missing-EKU) covered by 45
new tests. Shadowsocks AEAD gained an explicit replay-window check.
Command-injection / path-traversal fuzzing added to the FTP
translator + SFTP CLI.

### Unsafe-block audit (t8-D1, t8-D2, t8-D3, t8-D4)

All **160** `unsafe` blocks (114 in `crates/` + 46 in `vendor/`)
carry per-block `// SAFETY:` comments. Where a safe alternative
exists (`zerocopy 0.7`, `bytemuck`), the `unsafe` block was
replaced. `spt-bin/src/policy/registry.rs`'s 27-block cluster was
refactored to remove direct FFI in favour of the `windows-service`
crate's higher-level API. The `clippy::undocumented_unsafe_blocks`
lint is now `-D` workspace-wide.

### Supervisor reset_after + session-health fix (t8-FixSup)

The reconnect backoff state machine now resets the attempt counter
after a configurable stable-uptime threshold (`reconnect.reset_after`,
default `10m`), matching spec §11.2's "after stable interval, treat
the next failure as a fresh attempt". Session-health propagation no
longer races the state-machine transition table; the regression test
`reset_after_stable_uptime` locks the contract.

### Doc-warnings gate widens to `-D warnings` (t8-E1)

The CI doc gate, narrowed in t7-CCI to `-D rustdoc::missing-docs`
only, widens to `-D warnings` in t8-E1 after a workspace-wide
intra-doc-link sweep (~78 estimated, 61 measured, all repaired). The
remaining 7 crates that carried >50 missing-docs items each got
`#![warn(missing_docs)] + #![allow(missing_docs)]` with a documented
deferral to v1.1.

## Migration notes from 0.x

### libssh2 removed; russh is the only SSH2 backend

`ssh2`, `async-ssh2-lite`, `libssh2-sys`, and `openssl-src` are no
longer workspace dependencies (closed in t7-Phase0). On Linux/macOS
spt no longer needs system `libssl-dev` / `openssl@3` for its own
build; on Windows, Strawberry Perl is no longer required.

The deprecated keys `[capabilities].ssh2_backend` and
`[capabilities].allow_libssh2` still load with a one-shot warning
(`capabilities_ssh2_backend_deprecated_t7`) and are silently ignored.
Strip them with:

    spt config migrate --to 2

See `docs/migration/t7-to-t8.md` for the full transition guide.

### MSRV bump 1.83 → 1.85

The workspace MSRV moved from Rust 1.83 to **1.85** during t7 to
accommodate `sspi 0.15.12` and `cargo update` transitives. The B1
`ml-kem 0.3.2` dep also requires 1.85.

    rustup install 1.85.0
    rustup default 1.85.0

`rust-toolchain.toml` is pinned to channel `1.85` for toolchain-managed
builds.

### Algorithm parity

Deprecated algorithms libssh2 still shipped (`blowfish-cbc`,
`cast128-cbc`, `arcfour*`, `hmac-md5*`, `hmac-sha1-96`) are not in
russh. Losing them is a deliberate hardening. PQ-KEX (`mlkem*`,
`sntrup761x25519-sha512`) is live for ML-KEM as of t8; SNTRUP is
name-registered but the KEM primitive is deferred.

### New deps added during t8

| Crate                 | Version | Added by |
|-----------------------|---------|----------|
| `ml-kem`              | 0.3.2   | B1       |
| `miette`              | 7       | A1       |
| `zerocopy`            | 0.7     | D2       |
| `subtle`              | 2 (graph) | A6     |
| `criterion-table` (optional) | 0.4 | C4   |

No `pqcrypto-*` dep — the SNTRUP path is a documented operator
decision (see Known Issues).

## Known issues

These are tracked, scoped, and non-blocking for the 26.1 surface.
Per the rolling-release model, fixes ship as follow-up `v26.N`
releases — there is no batched "next major" to defer to.

### Crypto

* **`sntrup761x25519-sha512` KEM not yet implemented.** The hybrid
  KEX is name-registered in both canonical and `@openssh.com`-suffixed
  forms; the wire validator parses both INIT and REPLY blobs; the
  KEM primitive returns `Error::Kex` until one of three documented
  resume paths is chosen by the operator:
  1. Adopt `pqcrypto-sntruprime 0.7` (C-backed; ~½ day to wire up).
  2. Adopt `sntrup761 0.4.0` (pure-Rust; requires MSRV bump to 1.90
     and a security review).
  3. Hand-port from `openssh-portable/sntrup761.c` (~1 week +
     `dudect` / `ctgrind` pass).
  See `.orchestration/logs/t8-B2.md` for the full disposition.

* **libgssapi MIC known-vector test still a placeholder.** The
  vendored `libgssapi-fork` implements `gss_get_mic` /
  `gss_verify_mic` and rounds-trip against itself; the OpenSSH-server
  transcript fixture is reserved at
  `vendor/libgssapi-fork/libgssapi/tests/mic_vectors.rs` but not
  populated. Wire-compatibility with strict RFC 4462 §3.5 peers is
  asserted by the live `KERBEROS_LIVE=1` test path against MIT-KRB5.

### Obfuscation / interop

* **obfs4 NTOR wire-incompat with `obfs4proxy`** (surfaced by t8-A4).
  spt's obfs4 client subset diverges from the upstream
  reference implementation in two places: NTOR client-handshake epoch
  selection and `iat-mode 2` padding. Mode `2` is rejected with a
  structured error. See `crates/spt-obfs/README.md` § "obfs4
  compatibility" for the wire-spec delta.

* **Shadowsocks AAD divergence from SIP022** (surfaced by t8-A4).
  spt encodes per-record AAD as `len_u16 || timestamp_u32` where
  SIP022 specifies `len_u16` alone. The divergence was inherited
  from t6-e10's initial Shadowsocks client and is retained because
  the wire format must remain stable for already-deployed peers; a
  toggle `[obfs.shadowsocks].sip022_aad` is reserved for v1.1.

### Mount + transport edge cases

* **macOS SFTP mount permanently second-class.** The backend shells
  out to `sshfs` + macFUSE with a documented deprecation warning.
  `sshfs` opens its own SSH session; no connection-pool or keep-alive
  sharing with the in-process `spt` runtime. FSKit-based replacement
  is queued for a future rolling release.

* **FTP `..` silent-collapse** (surfaced by t8-A6). The FTP
  translator collapses `..` path segments at the translator boundary
  before forwarding to SFTP — a defense-in-depth measure that lets
  legitimate clients navigate up while preventing escape from the
  configured chroot. Operators relying on `..` reaching the SFTP
  server should set `[ftp_translator].pass_through_dotdot = true`.

* **CRL not consulted by pinned TLS** (surfaced by t8-A6). The
  `PinnedTlsConnector` validates against system roots + SPKI pins
  but does not consult CRL or OCSP. A pinned cert that has been
  revoked upstream will still pass spt's check. v1.1 adds OCSP
  stapling.

### Operational

* **`latency_spike_10ms_to_500ms` chaos timing** (surfaced by t8-FixSup).
  The scenario asserts reconnect-attempt distribution within ±5% on
  fast Linux runners. On heavily-loaded shared CI runners the
  variance has been observed up to ±18%. Quarantined behind
  `SPT_CHAOS_LATENCY_TOL=20` until a runtime-floor calibration lands.

* **4 chaos scenarios are Linux-only kernel-level**. Run under
  `SPT_CHAOS_FULL=1`. The remaining 8 scenarios run in default CI on
  all 6 OS/arch targets.

* **Upstream russh PR for `Signer::Future: 'static` is outstanding.**
  The patch is carried in the locally-vendored fork at
  `vendor/russh-fork/`. PR submission is tracked as future rolling-
  release work.

* **8 RUSTSEC ignores in `deny.toml`** — all MSRV / upstream-blocked,
  re-evaluated quarterly. See `deny.toml` comments for per-entry
  rationale.

## Verification

The following gates were green on the t8-E1 close-out commit. CI runs
the same gates on every PR + push across all 6 OS/arch targets
(Linux x86_64 + arm64, macOS Intel + Apple Silicon, Windows MSVC
x86_64 + arm64).

| Gate | Status |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo build --workspace --locked` | PASS |
| `cargo test --workspace --locked --no-fail-fast` | PASS (see `.orchestration/logs/t8-E1.md` for the per-crate matrix) |
| `cargo clippy --workspace --locked --all-targets -- -D warnings -D clippy::undocumented_unsafe_blocks` | PASS |
| `cargo doc --workspace --no-deps --locked` with `RUSTDOCFLAGS="-D warnings"` | PASS |
| `cargo deny check` | PASS (7 documented ignores, all re-evaluated post-PQ-deps) |

## Where to go for support

* **User docs**: `docs/getting-started.md`, `docs/configuration.md`,
  `docs/cli-reference.md`.
* **Production-readiness audit**: `docs/production_readiness.md`.
* **Migration**: `docs/migration/`, especially `t7-to-t8.md` for the
  libssh2 → russh transition.
* **Security**: `security.md` for the disclosure policy.
* **Issues**: project issue tracker. File against the closest
  matching workstream label.
* **Operator runbook**: `docs/troubleshooting.md` for common
  reconnect / auth / mount failures and the diagnostic commands that
  unpack them.

---

*This document accompanies the `v26.1` rolling-release tag. The
release artifact is regenerated by the `releasing.md` automation on
every green-CI push to `main`; any per-commit fix-ups land in
`changelog.md` against the corresponding `## [YY.N]` section once
the follow-up release ships.*

# Changelog

This project follows a **rolling release** model with `YY.N` versions
(two-digit UTC year + monotonic counter that resets each year). The
workspace `Cargo.toml` carries the SemVer-compatible `0.YY.N` form
because Cargo's TOML parser rejects the bare `YY.N` shape; user-
facing tags drop the leading `0.`. See [`releasing.md`](releasing.md)
and [`docs/releases/readme.md`](docs/releases/readme.md) for the full
scheme.

Releases are cut automatically by `.github/workflows/ci.yml` when the
full CI matrix and the security audit are green on a push to `main`.
Per-release notes live under [`docs/releases/`](docs/releases/); this
file is the rolled-up index. Entries are prepended by the release
job using `## [VERSION] - YYYY-MM-DD`. Dates are ISO 8601 (UTC).

## [Unreleased]

### Added

- (entries land here as PRs merge; keep them user-visible and
  imperative — "Add SRV record synthesis to the resolver", not
  "Refactored the resolver internals").

## [26.1] - 2026-05-22

Initial rolling release. `spt` ships as a single, batteries-included
Rust CLI for permanent SSH tunnels. Closes out milestones t6 (feature
surface), t7 (libssh2 demolished, contract stubs become real), and
t8 (production hardening). See [`docs/releases/26.1.md`](docs/releases/26.1.md)
for the full release notes (highlights, migration notes from the
pre-release `0.x` series, known issues, and verification gates).

### Added

- **SSH2 transport** via the pure-Rust `russh` stack (libssh2 removed
  in t7-Phase0) with full local and remote TCP forwarding, jump-host
  chains, agent + key auth, and a hardened trust store (`spt-trust`).
- **SSH3 transport** (experimental) over QUIC + HTTP/3, including
  per-forward channel framing, OIDC device-flow bearer auth
  (RFC 8628), and UDP forward support. Marked experimental and
  excluded from the security scope until standards-track.
- **Post-quantum KEX**: `mlkem768x25519-sha256` (FIPS 203 ML-KEM-768
  hybrid with X25519) live in the vendored russh fork, wire-compatible
  with OpenSSH 9.9's `kexmlkem768x25519.c`.
- **Chaos engineering**: new `spt-chaos-proxy` crate + 12 reconnect
  scenarios under `tests/chaos/` validating supervisor backoff against
  partitions, latency spikes, RST storms, DNS flapping, host-key
  churn, slow-loris, half-close, and rapid-reconnect storms.
- **Comparative performance**: `spt-benchmark` `Comparator` trait
  with `OpenSshClient` and `AutosshClient` implementations; a
  3×3×2×3 (54-cell) baseline matrix checked in at
  `docs/perf/baseline-26.1.json` (file path retained as
  `baseline-v1.0.json` in this release for backward-compat).
- Built-in transparent **DNS resolver** with split-horizon resolution,
  SRV record synthesis, and a managed-block hosts-file integrator.
- Encrypted **secret vault** (AES-256-GCM + Argon2id) with OS-keychain
  integration; references resolve through `secret://ns/name`. Secrets
  are zeroized end-to-end via `secrecy::SecretBox<Zeroizing<Vec<u8>>>`.
- **Service integration** for systemd, launchd, Windows SCM, OpenRC,
  SysV, and Windows Task Scheduler — full lifecycle (install, start,
  stop, status, reload, uninstall) on every backend.
- **Observability** stack: rotating file logs, journald, syslog-TLS,
  HTTPS-JSONL, OTLP traces + metrics, Prometheus exporter, and a
  project SNMPv3 agent + traps using the bundled `SPT-MIB`. Per-
  module `SPT_LOG` filter directives with SIGHUP / MCP runtime reload.
- **Diagnostics with miette spans**: error surfacing rewritten across
  the top 50 error sites; FFI boundaries get explicit `catch_unwind`
  panic boundaries.
- Embedded **Model Context Protocol** server: 16 read-only resources
  and 31 tools, disabled by default, read-only by default, never
  emits plaintext secrets through any transport.
- **TUI profile configurator** (`spt profile configure --tui`).
- **27-crate workspace**, every library crate publishing a `testing`
  Cargo feature with fixtures, builders, and mocks for sibling-crate
  use.
- **Packaging** for 8 release targets: `.deb`, `.rpm`, `.pkg`, `.msi`,
  plus tarballs for the remaining triples; multi-arch GHCR images.
  Homebrew, Scoop, Chocolatey, Snap, Flatpak, AUR, Winget, and Nix
  manifests included.
- 38 stable exit codes, complete CLI man-page set under
  `packaging/man/`, and a published spec (`spec.md`) covering the
  full surface area.

### Security

- **Constant-time review**: every secret-comparison call site audited
  (`spt-secrets`, `spt-auth::totp`, `spt-key`, `spt-trust::known_hosts`)
  with `subtle 2` threaded through. TLS pinning + cert-validation
  edge cases (chain depth, expired-cert, missing-EKU) covered by 45
  new tests. Shadowsocks AEAD gained an explicit replay-window check.
- **Unsafe-block audit**: all 160 `unsafe` blocks (114 in `crates/` +
  46 in `vendor/`) carry per-block `// SAFETY:` comments; the
  `clippy::undocumented_unsafe_blocks` lint is `-D` workspace-wide.
- **8 new fuzz targets** (`socks5_negotiate`, `http_connect_request`,
  `ftp_verb_parse`, `ssh3_jwt_jose_header`, `openssh_config_parse`,
  `forward_spec_parse`, `obfs4_frame_decode`, `shadowsocks_aead_decrypt`).
  PR-gating runtime is 90 s per target.
