# spt-obfs test fixtures

## obfs4 self-vectors (`tests/fixtures/obfs4-vectors.json`)

The JSON fixture under `tests/fixtures/obfs4-vectors.json` pins the
deterministic outputs of `spt_obfs::obfs4::ntor_kdf` and
`spt_obfs::obfs4::seal_frame` for a small set of fixed inputs. These are
**self-vectors**, not obfs4proxy reference vectors — see the module
doc-comment on `crates/spt-obfs/src/obfs4.rs` for the wire-compat caveat.

### Regenerating after an intentional KDF / framing change

If you intentionally modify the obfs4 KDF construction (e.g. switch to
HKDF-SHA256 from the RustCrypto `hkdf` crate, or change the
`OBFS4_PROTOID` constant) and need to roll the fixture:

```pwsh
cargo test -p spt-obfs --test obfs4_vectors -- --nocapture 2>&1 | \
  Select-String -Pattern "Computed (c2s|framed)"
```

Copy the printed hex strings into `expected_*_hex` fields of
`tests/fixtures/obfs4-vectors.json` and commit alongside the source
change. Reviewers should challenge any fixture-change PR that does NOT
also document why the wire shape needed to move.

### Capturing obfs4proxy reference vectors (future work)

The `ntor_handshake_obfs4proxy_reference_vector` test is currently
`#[ignore]`'d because our minimal client is not wire-compatible with
Yawning Angel's reference. `t8-FixObfs4` corrected the framing
primitive (ChaCha20-Poly1305 → XSalsa20-Poly1305 / NaCl secretbox)
but the NTOR construction still folds `B` into the HKDF salt rather
than producing two ECDH outputs and concatenating per spec, so the
client-hello bytes will still diverge. To enable real interop:

1. Install `obfs4proxy` (`apt install obfs4proxy` on Debian/Ubuntu, or
   `go install gitlab.com/yawning/obfs4.git/obfs4proxy@latest`).
2. Run a bridge against a fixed `node_id` and identity key:

   ```pwsh
   $env:TOR_PT_MANAGED_TRANSPORT_VER = "1"
   $env:TOR_PT_STATE_LOCATION       = "C:\tmp\obfs4"
   $env:TOR_PT_SERVER_BINDADDR     = "obfs4-127.0.0.1:54321"
   $env:TOR_PT_SERVER_TRANSPORTS   = "obfs4"
   $env:TOR_PT_ORPORT              = "127.0.0.1:8000"
   obfs4proxy --enableLogging --unsafeLogging --logLevel=DEBUG
   ```

3. Use a client harness (e.g. `obfs4-cli`) to drive a single handshake
   against the bridge and capture the client→server bytes via tcpdump:

   ```sh
   sudo tcpdump -i lo -w obfs4.pcap port 54321
   ```

4. Parse the pcap, extract the 84-byte `ClientHello` and 64-byte server
   reply, and embed them as a vector under
   `obfs4proxy_interop_vectors.vectors[]` in
   `tests/fixtures/obfs4-vectors.json`.

5. Replace the `panic!` body of
   `ntor_handshake_obfs4proxy_reference_vector` with the assertion
   logic, and drop the `#[ignore]` attribute.

Note: enabling this test will fail against the current
`crates/spt-obfs/src/obfs4.rs` implementation. A wire-compatible
rewrite of the NTOR construction (full `EXP(B,x) || EXP(Y,x)` mix —
the framing now matches per `t8-FixObfs4`) is the remaining
prerequisite. That work is **not in scope for t8-A4 or t8-FixObfs4** —
see the logs for the reported gap.

## libgssapi MIC vectors

See `vendor/libgssapi-fork/libgssapi/tests/mic_vectors.rs` and
`tests/fixtures/krb5-mic-vectors.json`.
