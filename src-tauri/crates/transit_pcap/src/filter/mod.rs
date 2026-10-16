//! The view-filter language.
//!
//! `tcp.port == 443 and ip.src == 10.0.0.0/24 and dns.rcode != 0`
//!
//! Ours end to end: the grammar, the tokenizer, the Pratt parser, the
//! field registry, the evaluator, and the documentation. The *shape* is
//! conventional — dotted field names and C-style operators — because
//! every network engineer already reads it and a novel syntax would cost
//! familiarity for nothing. The field names are derived from the RFCs
//! that define the protocols, not from any other analyzer's dictionary.
//! See the PCaps plan §5 and §11.
//!
//! Two properties worth knowing before reading further:
//!
//! - **No regex touches user input**, so there is no catastrophic-
//!   backtracking surface. Filters arrive from three places — a user
//!   typing, a finding's suggested drill-down, and a model reasoning
//!   about untrusted packet contents — and none of them should be able
//!   to hang the app.
//! - **Unknown fields are refused with a suggestion**, never treated as
//!   "matches nothing". A typo returning an empty packet list reads as
//!   "there is no such traffic", which is the wrong conclusion to hand
//!   someone chasing an outage.
//!
//! The separate **capture** filter (what `tcpdump` is told to record) is
//! plain BPF and is not this language — that syntax is libpcap's,
//! BSD-licensed, and universal.

pub mod eval;
pub mod parse;

pub use eval::{FieldSpec, Filter, REGISTRY};
pub use parse::{CmpOp, Expr, FilterError, Value};
