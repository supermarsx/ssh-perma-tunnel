# IANA Private Enterprise Number (PEN) Registration

This document is the operator-facing registration packet for obtaining the
project's own IANA Private Enterprise Number. The number is needed to
publish `mibs/SPT-MIB.txt` under a globally unique OID arc and to populate
`[observability.snmp].enterprise_id` in production deployments.

Until a PEN is assigned, the codebase uses **32473** -- the RFC 5612 /
RFC 9371 "documentation" PEN reserved by IANA for examples and templates --
as a deliberate placeholder. Shipping a product under PEN 32473 is
explicitly NOT permitted by those RFCs, so the swap below must happen
before any production release.

## Status

| Field          | Value                                                              |
| -------------- | ------------------------------------------------------------------ |
| State          | NOT YET FILED -- operator action required                          |
| Placeholder    | 32473 (RFC 5612 / RFC 9371 documentation PEN)                      |
| Assigned PEN   | _to be filled in after IANA returns the assignment_                |
| Date filed     | _to be filled in_                                                  |
| Date assigned  | _to be filled in_                                                  |
| IANA ticket ID | _to be filled in (you will receive an `RT #...` number by email)_  |

## Where to file

IANA's Private Enterprise Number application form lives at:

- **<https://pen.iana.org/pen/PenApplication.page>**

(The older URL `https://www.iana.org/assignments/enterprise-numbers/assignment`
redirects to the form above. Some older guides reference
`iana-pen@iana.org` -- email submission has been deprecated; use the web
form.)

The form is short -- a single page -- and is processed by humans at IANA.
There is no fee for a PEN.

## Timeline

IANA's published Service Level Agreement for PEN requests is "within a few
business days" but actual turnaround historically ranges from **same-day to
2 business weeks**, depending on backlog and whether IANA requests
clarification. Expect 5--10 business days as the realistic median.

You will receive:

1. An auto-acknowledgement email with an `RT #...` ticket ID within minutes.
2. A human reply either asking for clarification or returning the assigned
   PEN as a decimal integer (e.g. `60123`).

## Application packet

Fill in the form with the following values. Fields marked `<MAINTAINER>`
must be filled in by the project maintainer at submission time -- this
document is checked in to the repository and should not contain personal
contact details.

| Form field                                | Value                                                                |
| ----------------------------------------- | -------------------------------------------------------------------- |
| Organization Name                         | `spt project`                                                        |
| Organization Address (line 1, optional)   | `<MAINTAINER>`                                                       |
| Organization Address (city / state / zip) | `<MAINTAINER>`                                                       |
| Organization Address (country)            | `<MAINTAINER>`                                                       |
| Contact Person -- Name                    | `<MAINTAINER>` (the person IANA will reply to)                       |
| Contact Person -- Email                   | `<MAINTAINER>` (a durable address, ideally a project alias)          |
| Contact Person -- Phone (optional)        | `<MAINTAINER>` or leave blank                                        |
| OID requested                             | _not user-selectable -- IANA assigns the next available integer_     |

In the free-text "Purpose" or "Brief description" field (the form's exact
label has varied over the years), use the following text verbatim:

> The spt project (https://github.com/Mariana/ssh-perma-tunnel) is an
> open-source SSH permanent-tunnel daemon. We require an IANA Private
> Enterprise Number to publish an SNMPv2 MIB module (SPT-MIB) under a
> globally unique OID arc, and to generate RFC 3411 §5.1 format-5 SNMP
> engine IDs for the bundled SNMPv3 USM agent (crate `spt-snmp`). The MIB
> defines pollable scalars and ten notification types covering process,
> profile, forward, authentication, trust, failover, DNS, rate-limit, and
> remote-log status of the spt daemon. The MIB source is checked in at
> `mibs/SPT-MIB.txt` and currently uses the RFC 5612 documentation PEN
> 32473 as a placeholder.

## After IANA assigns the PEN

When IANA returns the assigned number (call it `<NEW_PEN>`), run the
provided swap script. It edits exactly two files:

```sh
# POSIX (bash / zsh):
scripts/swap-pen.sh <NEW_PEN>

# Windows / PowerShell 7+:
scripts/swap-pen.ps1 <NEW_PEN>
```

The script rewrites:

1. The single `::= { enterprises 32473 }` line on the `spt MODULE-IDENTITY`
   in `mibs/SPT-MIB.txt`.
2. The single `SPT_ENTERPRISE_OID_PLACEHOLDER` constant body in
   `crates/spt-snmp/src/lib.rs`.

It leaves `.bak` files alongside each edited file. After verifying the diff,
delete the `.bak` files, then:

1. **Bump the MIB revision.** In `mibs/SPT-MIB.txt`, update
   `LAST-UPDATED` to the swap date in `YYYYMMDDhhmmZ` form and add a new
   `REVISION` / `DESCRIPTION` pair above the existing initial-revision pair.
   Example:

   ```text
   REVISION    "<NEW-DATE>"
   DESCRIPTION "Switched to IANA-assigned PEN <NEW_PEN>."
   REVISION    "202605050000Z"
   DESCRIPTION "Initial revision."
   ```

2. **Update this document.** Fill in the "Assigned PEN", "Date assigned",
   and "IANA ticket ID" rows in the status table above. Change the "State"
   row from `NOT YET FILED` to `ASSIGNED`.

3. **Verify the build.** From the repo root:

   ```sh
   cargo build --workspace --locked
   cargo test -p spt-snmp --locked
   cargo clippy -p spt-snmp --locked -- -D warnings
   ```

4. **Optional but recommended -- run `smilint`.** If `smilint` (from the
   `libsmi` package) is installed, run:

   ```sh
   smilint -s -l 6 mibs/SPT-MIB.txt
   ```

   Severity level 6 covers all SMIv2 rules. The MIB should be clean except
   for any warnings about the placeholder PEN if the swap was not done.

5. **Commit** the change in a single commit with subject
   `snmp: swap to IANA-assigned PEN <NEW_PEN>` and reference this document
   plus the IANA `RT #...` ticket ID in the body.

## Why a single-edit anchor matters

All subtree OIDs in `mibs/SPT-MIB.txt` are anchored at the symbolic
`spt MODULE-IDENTITY`, and `spt` is itself anchored at `{ enterprises
32473 }`. There is **exactly one** occurrence of the literal number `32473`
that participates in the OID structure (the `::= { enterprises 32473 }`
line); every other appearance in the MIB is inside a comment that
explicitly references the placeholder, and the `swap-pen` script's
sanity check looks for the structural occurrence specifically. This keeps
the swap deterministic and reviewable -- a single semantic change touching
exactly two files.
