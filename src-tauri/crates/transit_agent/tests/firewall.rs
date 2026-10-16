//! Compile-fail assertion that `transit_agent` cannot import from
//! `transit_auth`. The Cargo workspace structure (no `transit_auth`
//! dep on `transit_agent`) is the primary enforcement; `cargo deny`
//! `[[bans.deny]]` is the second; this test is the third.
//!
//! If this test starts passing (i.e., the compile-fail file actually
//! compiles), it means someone added `transit_auth` to
//! `transit_agent`'s dependencies. That's a security regression — the
//! one-way edge is what makes the agent firewall a property of the
//! type system instead of a comment.

#[test]
fn cant_import_transit_auth() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/firewall/cant_import_transit_auth.rs");
}
