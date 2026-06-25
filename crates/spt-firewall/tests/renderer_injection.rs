//! Security regression tests for the firewall renderers (W1-A).
//!
//! The rule `id` is operator-controlled (it flows from `profile.name` /
//! `forward.name` in `spt-bin/src/cli/firewall_ops.rs`) and is interpolated into
//! every backend's rendered rule: `name="spt:<id>"` (netsh), `comment "spt:<id>"`
//! (nft / iptables), and `label "spt:<id>"` (pf). The `interface` and
//! `source/dest CIDR` fields are likewise operator/config-controlled and
//! interpolated into `iif "<iface>"`, `-i <iface>`, `-s <cidr>`, etc.
//!
//! Without validation, an `id` such as `x" enable=yes; rm -rf /` or one
//! containing a space, quote, `;`, newline, `&`, backtick, `$()` could break out
//! of the quoted token and inject an additional rule field or directive — even
//! though rules are not run through a shell, netsh re-splits the rendered line on
//! whitespace into argv (see `windows.rs::netsh_add_commands` /
//! `cmd.split_whitespace()`), so an injected space/quote IS an extra argument.
//!
//! Defense is two-layer and these tests pin both:
//!   1. `validate_rule` / `validate_rules` reject bad input at the boundary
//!      (fail-closed with a clear error).
//!   2. `normalize` (used by every `plan()`) drops any rule that fails
//!      validation, so a malformed field can never reach a rendered command even
//!      if a caller forgets to validate.
//!
//! Fully hermetic: only the pure `plan()` dry-run render is exercised — never
//! `apply()` (no privileged shell-out).

use spt_firewall::{
    linux::{IptablesPlanner, NftPlanner},
    macos::PfPlanner,
    validate_rule, validate_rules,
    windows::NetshPlanner,
    Action, Direction, FirewallPlanner, Protocol, Rule, RuleValidationError, MAX_ID_LEN,
    MAX_INTERFACE_LEN,
};

/// Build an otherwise-valid inbound TCP rule with the given `id`.
fn rule_with_id(id: &str) -> Rule {
    Rule {
        id: id.to_string(),
        direction: Direction::In,
        action: Action::Allow,
        protocol: Protocol::Tcp,
        source_cidr: None,
        source_port: None,
        dest_cidr: None,
        dest_port: Some(2525),
        interface: None,
    }
}

/// Build a valid rule with the given interface name.
fn rule_with_interface(iface: &str) -> Rule {
    let mut r = rule_with_id("valid-id");
    r.interface = Some(iface.to_string());
    r
}

/// Build a valid rule with the given source CIDR.
fn rule_with_source_cidr(cidr: &str) -> Rule {
    let mut r = rule_with_id("valid-id");
    r.source_cidr = Some(cidr.to_string());
    r
}

/// Build a valid rule with the given destination CIDR.
fn rule_with_dest_cidr(cidr: &str) -> Rule {
    let mut r = rule_with_id("valid-id");
    r.dest_cidr = Some(cidr.to_string());
    r
}

/// Render each backend's plan for a slice of rules and return the four scripts
/// (nft, iptables, pf, netsh).
fn render_all(rules: &[Rule]) -> Vec<String> {
    vec![
        NftPlanner::new().plan(rules).script,
        IptablesPlanner::new().plan(rules).script,
        PfPlanner::new().plan(rules).script,
        NetshPlanner::new().plan(rules).script,
    ]
}

/// The collection of injection payloads we require to be rejected by validation.
/// Covers: space, double quote, `;`, newline, carriage return, `&`, backtick,
/// `$()`, path traversal `../`, single quote, pipe, and a non-ASCII unicode
/// character (which could smuggle a separator past a naive byte check).
fn injection_ids() -> Vec<(&'static str, String)> {
    vec![
        ("space", "spt rule".to_string()),
        ("double-quote", "x\" enable=yes name=\"y".to_string()),
        ("single-quote", "x' OR '1".to_string()),
        ("semicolon", "x; rm -rf /".to_string()),
        ("newline", "x\nnetsh delete all".to_string()),
        ("carriage-return", "x\rnetsh".to_string()),
        ("ampersand", "x & calc".to_string()),
        ("backtick", "x`whoami`".to_string()),
        ("dollar-paren", "x$(whoami)".to_string()),
        ("dollar-brace", "x${HOME}".to_string()),
        ("path-traversal", "../../etc/passwd".to_string()),
        ("pipe", "x|y".to_string()),
        ("tab", "x\ty".to_string()),
        ("forward-slash", "spt/rule".to_string()),
        ("backslash", "spt\\rule".to_string()),
        ("at-sign", "spt@rule".to_string()),
        ("colon", "spt:rule".to_string()),
        ("unicode-fullwidth-quote", "x\u{ff02}y".to_string()),
        ("null-ish-control", "x\u{0000}y".to_string()),
    ]
}

// --------------------------------------------------------------------------
// 1. Boundary validation: every injection id is rejected with a clear error.
// --------------------------------------------------------------------------

#[test]
fn validate_rejects_every_injection_id() {
    for (label, id) in injection_ids() {
        let r = rule_with_id(&id);
        let err = validate_rule(&r)
            .expect_err(&format!("injection id {label:?} ({id:?}) must be rejected"));
        // All of these contain a char outside [A-Za-z0-9._-].
        assert!(
            matches!(err, RuleValidationError::IdBadChar { .. }),
            "id {label:?} should fail with IdBadChar, got {err:?}"
        );
    }
}

#[test]
fn validate_accepts_well_formed_ids() {
    for id in [
        "smtp-in",
        "profile.fwd.1",
        "Web_Server-443",
        "a",
        "ABC123",
        "1-2-3",
    ] {
        let r = rule_with_id(id);
        validate_rule(&r).unwrap_or_else(|e| panic!("valid id {id:?} rejected: {e}"));
    }
}

#[test]
fn validate_rejects_empty_id() {
    let r = rule_with_id("");
    assert_eq!(validate_rule(&r), Err(RuleValidationError::EmptyId));
}

#[test]
fn validate_accepts_max_length_id_and_rejects_one_over() {
    let at_max = "a".repeat(MAX_ID_LEN);
    validate_rule(&rule_with_id(&at_max)).expect("id at MAX_ID_LEN must be accepted");

    let over = "a".repeat(MAX_ID_LEN + 1);
    assert_eq!(
        validate_rule(&rule_with_id(&over)),
        Err(RuleValidationError::IdTooLong {
            len: MAX_ID_LEN + 1
        })
    );
}

#[test]
fn validate_rules_returns_first_failure_and_is_fail_closed() {
    let rules = vec![
        rule_with_id("good-1"),
        rule_with_id("bad id with space"),
        rule_with_id("good-2"),
    ];
    let err = validate_rules(&rules).expect_err("a bad rule in the set must fail the whole set");
    assert!(matches!(err, RuleValidationError::IdBadChar { ch } if ch == ' '));

    // All-valid set passes.
    validate_rules(&[rule_with_id("good-1"), rule_with_id("good-2")]).expect("all-valid set");
}

// --------------------------------------------------------------------------
// 2. Interface field validation.
// --------------------------------------------------------------------------

#[test]
fn validate_rejects_injection_interface() {
    for iface in [
        "eth0; rm -rf /",
        "eth0\"",
        "eth 0",
        "eth0\nx",
        "eth0`id`",
        "eth0$(x)",
        "../dev",
        "eth0|x",
    ] {
        let r = rule_with_interface(iface);
        assert!(
            validate_rule(&r).is_err(),
            "injection interface {iface:?} must be rejected"
        );
    }
}

#[test]
fn validate_accepts_legitimate_interface_names() {
    // The interface allowlist additionally permits ':' (VLAN sub-interface) and
    // '@' (nft/macOS aliasing).
    for iface in ["eth0", "en0", "eth0:1", "wg0", "veth@if5", "tun.0"] {
        let r = rule_with_interface(iface);
        validate_rule(&r).unwrap_or_else(|e| panic!("valid interface {iface:?} rejected: {e}"));
    }
}

#[test]
fn validate_rejects_empty_and_overlong_interface() {
    assert_eq!(
        validate_rule(&rule_with_interface("")),
        Err(RuleValidationError::EmptyInterface)
    );
    let over = "a".repeat(MAX_INTERFACE_LEN + 1);
    assert_eq!(
        validate_rule(&rule_with_interface(&over)),
        Err(RuleValidationError::InterfaceTooLong {
            len: MAX_INTERFACE_LEN + 1
        })
    );
    validate_rule(&rule_with_interface(&"a".repeat(MAX_INTERFACE_LEN)))
        .expect("interface at max len accepted");
}

// --------------------------------------------------------------------------
// 3. CIDR / address field validation.
// --------------------------------------------------------------------------

#[test]
fn validate_rejects_injection_and_malformed_cidrs() {
    for bad in [
        "999.999.999.999/32",
        "10.0.0.0/33",
        "10.0.0.0/8; drop",
        "10.0.0.0/8 accept",
        "10.0.0.0/8\nx",
        "$(whoami)",
        "any",
        "10.0.0.0/8\"",
        "not-an-ip",
    ] {
        assert!(
            validate_rule(&rule_with_source_cidr(bad)).is_err(),
            "malformed/injection source cidr {bad:?} must be rejected"
        );
        assert!(
            validate_rule(&rule_with_dest_cidr(bad)).is_err(),
            "malformed/injection dest cidr {bad:?} must be rejected"
        );
    }
}

#[test]
fn validate_accepts_valid_cidrs_and_bare_addresses() {
    for ok in [
        "10.0.0.0/8",
        "127.0.0.1/32",
        "127.0.0.1",
        "::1/128",
        "::1",
        "2001:db8::/32",
        "0.0.0.0/0",
    ] {
        validate_rule(&rule_with_source_cidr(ok))
            .unwrap_or_else(|e| panic!("valid source cidr {ok:?} rejected: {e}"));
        validate_rule(&rule_with_dest_cidr(ok))
            .unwrap_or_else(|e| panic!("valid dest cidr {ok:?} rejected: {e}"));
    }
}

#[test]
fn validate_cidr_error_reports_which_side() {
    match validate_rule(&rule_with_source_cidr("bogus")) {
        Err(RuleValidationError::BadCidr { which, .. }) => assert_eq!(which, "source"),
        other => panic!("expected BadCidr(source), got {other:?}"),
    }
    match validate_rule(&rule_with_dest_cidr("bogus")) {
        Err(RuleValidationError::BadCidr { which, .. }) => assert_eq!(which, "dest"),
        other => panic!("expected BadCidr(dest), got {other:?}"),
    }
}

// --------------------------------------------------------------------------
// 4. Renderer defense-in-depth: invalid rules NEVER reach a rendered command.
//    Each backend's plan() runs `normalize`, which drops failing rules.
// --------------------------------------------------------------------------

#[test]
fn renderers_drop_every_injection_id_no_directive_leaks() {
    for (label, id) in injection_ids() {
        // One good rule + one injection rule. The good rule must render; the
        // injection rule must be dropped entirely from every backend.
        let rules = vec![rule_with_id("good-rule"), rule_with_id(&id)];
        for script in render_all(&rules) {
            // The valid rule is present.
            assert!(
                script.contains("good-rule"),
                "[{label}] valid rule missing from script:\n{script}"
            );
            // No fragment of the injection payload appears anywhere — neither
            // the raw id nor any distinctive injected token.
            for needle in [
                "rm -rf",
                "enable=yes name=",
                "whoami",
                "delete all",
                "calc",
                "/etc/passwd",
                "${HOME}",
            ] {
                assert!(
                    !script.contains(needle),
                    "[{label}] injection fragment {needle:?} leaked into script:\n{script}"
                );
            }
        }
    }
}

/// The double-quote payload is the canonical netsh break-out: `x" enable=yes
/// name="y`. Assert it produces NO extra `name="` token in the netsh script
/// (which would be a second, attacker-chosen rule name).
#[test]
fn netsh_quote_breakout_cannot_inject_second_name_token() {
    let evil = rule_with_id("x\" enable=yes name=\"evil");
    let plan = NetshPlanner::new().plan(&[rule_with_id("legit"), evil]);
    // Exactly one rendered rule line (the legit one); the evil rule is dropped.
    let name_count = plan.script.matches("name=\"").count();
    assert_eq!(
        name_count, 1,
        "exactly one name= token expected (evil rule dropped), got {name_count}:\n{}",
        plan.script
    );
    assert!(plan.script.contains("name=\"spt:legit\""));
    assert_eq!(plan.rule_count, 1, "evil rule must not be counted");
}

/// The newline payload is the canonical nft/pf/iptables break-out: a second
/// line that would be a fresh directive. Assert no backend renders an extra
/// line carrying the injected text.
#[test]
fn newline_payload_cannot_inject_extra_line() {
    let evil = rule_with_id("x\naccept comment \"spt:evil");
    for (planner_name, script) in [
        ("nft", NftPlanner::new().plan(&[evil.clone()]).script),
        (
            "iptables",
            IptablesPlanner::new().plan(&[evil.clone()]).script,
        ),
        ("pf", PfPlanner::new().plan(&[evil.clone()]).script),
        ("netsh", NetshPlanner::new().plan(&[evil.clone()]).script),
    ] {
        assert!(
            !script.contains("spt:evil"),
            "[{planner_name}] newline-injected directive leaked:\n{script}"
        );
    }
}

/// An injection-bearing interface must also be dropped by every renderer, so no
/// `iif`/`-i`/`on`/interface fragment carrying the payload is emitted.
#[test]
fn renderers_drop_injection_interface() {
    let evil = rule_with_interface("eth0\" ; rm -rf /");
    for script in render_all(&[rule_with_id("good"), evil]) {
        assert!(script.contains("good"));
        assert!(
            !script.contains("rm -rf"),
            "interface injection leaked:\n{script}"
        );
    }
}

/// An injection-bearing CIDR must be dropped (it never parses as an address).
#[test]
fn renderers_drop_injection_cidr() {
    let mut evil = rule_with_id("evil-cidr");
    evil.dest_cidr = Some("10.0.0.0/8 accept; drop".to_string());
    for script in render_all(&[rule_with_id("good"), evil]) {
        assert!(script.contains("good"));
        assert!(
            !script.contains("accept; drop") && !script.contains("10.0.0.0/8 accept"),
            "cidr injection leaked:\n{script}"
        );
    }
}

// --------------------------------------------------------------------------
// 5. Valid-input behavior is preserved (no regression for legitimate rules).
// --------------------------------------------------------------------------

#[test]
fn valid_rule_renders_expected_tokens_each_backend() {
    let mut r = rule_with_id("smtp-in");
    r.source_cidr = Some("10.0.0.0/8".to_string());
    r.interface = Some("eth0".to_string());
    let rules = vec![r];

    let nft = NftPlanner::new().plan(&rules).script;
    assert!(nft.contains("comment \"spt:smtp-in\""));
    assert!(nft.contains("iif \"eth0\""));
    assert!(nft.contains("ip saddr 10.0.0.0/8"));
    assert!(nft.contains("tcp dport 2525"));

    let ipt = IptablesPlanner::new().plan(&rules).script;
    assert!(ipt.contains("--comment \"spt:smtp-in\""));
    assert!(ipt.contains("-i eth0"));
    assert!(ipt.contains("-s 10.0.0.0/8"));

    let pf = PfPlanner::new().plan(&rules).script;
    assert!(pf.contains("label \"spt:smtp-in\""));
    assert!(pf.contains("on eth0"));
    assert!(pf.contains("from 10.0.0.0/8"));

    let netsh = NetshPlanner::new().plan(&rules).script;
    assert!(netsh.contains("name=\"spt:smtp-in\""));
    assert!(netsh.contains("remoteip=10.0.0.0/8"));
    assert!(netsh.contains("localport=2525"));
}

#[test]
fn empty_ruleset_renders_well_formed_per_backend() {
    // nft still emits the table scaffold; the others a header only. None panic,
    // all report zero rules.
    for planner in [
        Box::new(NftPlanner::new()) as Box<dyn FirewallPlanner>,
        Box::new(IptablesPlanner::new()),
        Box::new(PfPlanner::new()),
        Box::new(NetshPlanner::new()),
    ] {
        let plan = planner.plan(&[]);
        assert_eq!(plan.rule_count, 0);
        assert!(!plan.script.is_empty());
    }
}

#[test]
fn max_rules_all_render_when_valid() {
    // A larger valid set renders fully (no silent truncation of legit rules).
    let rules: Vec<Rule> = (0..256)
        .map(|i| rule_with_id(&format!("rule-{i}")))
        .collect();
    for planner in [
        Box::new(NftPlanner::new()) as Box<dyn FirewallPlanner>,
        Box::new(IptablesPlanner::new()),
        Box::new(PfPlanner::new()),
        Box::new(NetshPlanner::new()),
    ] {
        let plan = planner.plan(&rules);
        assert_eq!(plan.rule_count, 256, "all 256 valid rules must render");
    }
}

#[test]
fn dry_run_apply_is_a_noop_for_every_backend() {
    let rules = vec![rule_with_id("smtp-in")];
    for planner in [
        Box::new(NftPlanner::new()) as Box<dyn FirewallPlanner>,
        Box::new(IptablesPlanner::new()),
        Box::new(PfPlanner::new()),
        Box::new(NetshPlanner::new()),
    ] {
        let plan = planner.plan(&rules);
        planner
            .apply(&plan, true)
            .expect("dry-run apply must succeed without shelling out");
    }
}
