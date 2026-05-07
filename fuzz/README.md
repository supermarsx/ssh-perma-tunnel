# spt-fuzz

Coverage-guided fuzz targets for the parsers and protocol decoders in
ssh-perma-tunnel. Built with [`cargo-fuzz`] / libFuzzer.

## Layout

This crate is **its own workspace** — decoupled from the main one (which is
pinned to MSRV 1.83). The main `Cargo.toml` excludes `fuzz/`, so plain
`cargo build` at the repo root never touches this directory. cargo-fuzz
requires nightly Rust to build the libFuzzer instrumentation; the rest of
the project stays on stable.

```
fuzz/
  Cargo.toml             # separate workspace, name = "spt-fuzz"
  fuzz_targets/<name>.rs # one binary per target
  corpus/<name>/         # seed inputs (one dir per target)
  artifacts/<name>/      # crashes/leaks/timeouts (created on first hit)
```

## Targets

| Target              | Crate / function under test                                      |
|---------------------|------------------------------------------------------------------|
| `toml_config`       | `spt_config::load::load_str` (strict + lenient)                  |
| `ber_decode`        | `spt_snmp::ber::{Decoder, decode_oid}`                           |
| `snmpv3_message`    | `spt_snmp::message::{Message, ScopedPdu, SecurityParameters}::*` |
| `usm_authenticate`  | `spt_snmp::usm::{auth_digest, password_to_key, derive_keys}`     |
| `ssh3_frame`        | `spt_ssh3::frame::{Ssh3Frame, *Payload, Ssh3Settings}::decode*`  |
| `address_parse`     | `spt_core::address::BindAddr::from_str`                          |
| `duration_parse`    | `spt_core::duration::parse_duration`                             |
| `size_parse`        | `spt_core::size::parse_size`                                     |
| `redaction`         | `spt_core::redaction::redact` (None/Standard/Strict)             |
| `known_hosts`       | `spt_trust::KnownHosts::parse`                                   |

## Install

```sh
rustup install nightly
rustup component add --toolchain nightly rust-src
cargo install cargo-fuzz --locked
```

(libFuzzer is bundled with `rustc` nightly; `rust-src` is needed by
cargo-fuzz to rebuild the standard library with sanitizers.)

## Run a target

```sh
cd fuzz
cargo +nightly fuzz run toml_config
```

By default this loops forever — interrupt with Ctrl-C. To bound the run:

```sh
cargo +nightly fuzz run toml_config -- -max_total_time=300   # 5 minutes
cargo +nightly fuzz run toml_config -- -runs=100000          # 100k iterations
```

The seed corpus under `corpus/<target>/` is loaded automatically; libFuzzer
writes new interesting inputs back into the same directory as it discovers
new coverage.

## Triage a crash

When libFuzzer hits a crash, leak, or timeout it writes a reproducer to
`fuzz/artifacts/<target>/<crash-hash>` and prints the path. To minimize and
re-run that input:

```sh
cd fuzz
# Minimize (libFuzzer's tmin: shrink the input while keeping the crash).
cargo +nightly fuzz tmin toml_config artifacts/toml_config/crash-<hash>

# Reproduce (just feed the input back in once).
cargo +nightly fuzz run toml_config artifacts/toml_config/crash-<hash>

# Pretty-print the input (TOML/text targets).
cargo +nightly fuzz fmt toml_config artifacts/toml_config/crash-<hash>
```

For a stack trace with source lines, run with `RUST_BACKTRACE=1`.

## Add a new target

1. Pick a public function under `crates/<crate>/src/` whose only input is
   bytes or a string. Decoders are great candidates; functions with rich
   side effects (filesystem, network) are not.
2. Create `fuzz_targets/<name>.rs` (use any existing target as a template).
   Keep the body minimal — call the function under test inside `fuzz_target!`,
   ignore the result, and don't `unwrap`.
3. Register the binary in this crate's `Cargo.toml`:

   ```toml
   [[bin]]
   name = "<name>"
   path = "fuzz_targets/<name>.rs"
   test = false
   doc = false
   bench = false
   ```

4. Seed the corpus: `mkdir corpus/<name>/` and drop in 2–3 representative
   inputs (any reasonable bytes work — they don't have to parse).
5. Add `<name>` to the `matrix.target` list in
   `.github/workflows/fuzz.yml` so PRs touching the relevant crate exercise
   the new target.

## Corpus generators

The seed corpora under `corpus/<target>/` are produced by the small CLI
crate at `fuzz/generators/`. It is **its own workspace** (decoupled from
both the main crate and the fuzz crate) so it can pull modern dep versions
without affecting either MSRV contract.

Each generator emits a hand-curated set of 20–45 files: representative
valid inputs (round-tripped through the production parser to confirm
they actually parse) plus a deliberate set of boundary cases (empty,
truncated, max-length, all-zero/0xFF, BOM, RTL mark, NUL byte, recursively
nested where the format allows). Diversity > volume: libFuzzer mutates
from these seeds, so a small diverse set is more useful than a huge
random one.

### Regenerate one corpus

```sh
# From repo root.
cd fuzz/generators
cargo run --bin gen-toml-config -- ../corpus/toml_config/
```

The mapping between generator and corpus directory:

| Generator              | Output corpus dir              |
|------------------------|--------------------------------|
| `gen-toml-config`      | `corpus/toml_config/`          |
| `gen-ber`              | `corpus/ber_decode/`           |
| `gen-snmpv3-message`   | `corpus/snmpv3_message/`       |
| `gen-usm`              | `corpus/usm_authenticate/`     |
| `gen-ssh3-frame`       | `corpus/ssh3_frame/`           |
| `gen-known-hosts`      | `corpus/known_hosts/`          |
| `gen-addresses`        | `corpus/address_parse/`        |
| `gen-durations`        | `corpus/duration_parse/`       |
| `gen-sizes`            | `corpus/size_parse/`           |
| `gen-redact`           | `corpus/redaction/`            |

### Regenerate all corpora

```sh
cd fuzz/generators
for g in toml-config ber snmpv3-message usm ssh3-frame known-hosts \
         addresses durations sizes redact; do
  case $g in
    toml-config)     t=toml_config ;;
    ber)             t=ber_decode ;;
    snmpv3-message)  t=snmpv3_message ;;
    usm)             t=usm_authenticate ;;
    ssh3-frame)      t=ssh3_frame ;;
    known-hosts)     t=known_hosts ;;
    addresses)       t=address_parse ;;
    durations)       t=duration_parse ;;
    sizes)           t=size_parse ;;
    redact)          t=redaction ;;
  esac
  cargo run --quiet --bin gen-$g -- ../corpus/$t/
done
```

Generators are idempotent: re-running overwrites the same filenames with
the same content. New files dropped into the corpus by libFuzzer (during
a fuzzing run) are not touched as long as their names don't collide with
generator-emitted ones (generators always prefix with `valid_` or
`boundary_`; libFuzzer uses content-hash filenames).

### How libFuzzer uses the corpus

libFuzzer loads everything under `corpus/<target>/` at startup, replaying
each file once to build coverage state. Files that hit new edges become
"interesting"; libFuzzer then mutates them (bit-flips, byte-arithmetic,
crossover, splice) to discover further edges. A diverse seed set short-
circuits the cold-start phase: instead of the fuzzer having to *first
discover* what a valid TOML or SNMPv3 envelope looks like by mutating
random bytes for hours, it begins with a basin of valid shapes and only
needs to find the edge cases.

### What "good corpus diversity" means here

For spt's parsers specifically:

- **Every code path the harness exercises** should have at least one
  valid seed reaching it. Example: the BER decoder has separate paths
  for `read_i64`, `read_u32`, `read_octet_string`, `read_null`,
  `read_oid`, `read_counter64`, `read_app_u32`, `read_sequence`, and the
  generic `read_tlv` walker. The BER corpus has ≥1 seed that successfully
  decodes through each.
- **Every variant of a sum type** (PDU kind, frame kind, value type,
  auth method, redaction mode) should appear in at least one valid seed.
- **Length-encoding boundaries** — short-form vs long-form BER lengths,
  u16/u32 boundaries, multi-byte UTF-8, IDN/punycode hosts.
- **Structural extremes** — empty collections, deeply-nested structures,
  duplicate keys, all-zero / all-`0xFF` inputs.
- **Charset edge cases for text formats** — BOM, RTL marks, NUL bytes,
  unicode keys/values.

### Adding a new generator

1. Add a new `[[bin]]` entry to `fuzz/generators/Cargo.toml` and create
   `fuzz/generators/src/bin/gen-<name>.rs`.
2. Use `spt_fuzz_generators::out_dir_from_args` and
   `spt_fuzz_generators::write_file` from the sibling `lib.rs`.
3. For each "valid" seed: build the structured value, run it through the
   real encoder, and round-trip-parse the bytes to confirm before writing.
4. Add 5–10 hand-crafted boundary seeds with `boundary_*` filenames.
5. Add the new generator to the loop in this README and to
   `.orchestration/logs/f-prop-corpus.md`.

## Notes

- The fuzz crate is intentionally a separate workspace: cargo-fuzz needs
  nightly + sanitizers, while the main workspace is committed to MSRV 1.83.
  Don't add `fuzz/` to the main `[workspace] members`.
- Don't run `cargo update` — this crate's lockfile (when one is generated)
  is independent of the main workspace's pinned dep graph.
- All targets are written to **never panic** on arbitrary input. A hit
  during fuzzing is a real bug — open an issue with the reproducer.

[`cargo-fuzz`]: https://rust-fuzz.github.io/book/cargo-fuzz.html
