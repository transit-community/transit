//! View-filter tokenizer and parser.
//!
//! The grammar is ours. It is *conventional* — dotted field names, C-style
//! comparison operators, `and`/`or`/`not` — because every network engineer
//! already reads `tcp.port == 443` and inventing a novel syntax would cost
//! familiarity for nothing. But the grammar, this parser, the field
//! registry and the documentation are all written here from the protocol
//! RFCs, not derived from another analyzer's dictionary (plan §5, §11).
//!
//! ```text
//! expr        := or
//! or          := and (('or' | '||') and)*
//! and         := unary (('and' | '&&') unary)*
//! unary       := ('not' | '!') unary | primary
//! primary     := '(' expr ')' | comparison | presence
//! comparison  := field op value
//! presence    := field                      // "the field exists"
//! op          := '==' '!=' '>' '>=' '<' '<=' 'contains' 'in'
//! value       := number | ip | cidr | mac | quoted | bareword | set
//! set         := '{' value (',' value)* '}'
//! ```
//!
//! # No regex on user input
//!
//! The tokenizer is a hand-written character scanner and the parser is a
//! small Pratt parser. Nothing here compiles a user-supplied string into a
//! regex, so there is no catastrophic-backtracking surface — which matters
//! because a filter can be typed by a user, saved in a finding, or (via
//! `query_capture`) proposed by a model reasoning about untrusted packet
//! contents.
//!
//! # Errors carry a position
//!
//! Every error knows where it happened, so the filter bar can underline
//! the offending token instead of saying "invalid filter".

use std::fmt;
use std::net::IpAddr;

/// Why a filter would not parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterError {
    pub message: String,
    /// Byte offset into the filter text where the problem starts.
    pub at: usize,
}

impl FilterError {
    pub(crate) fn new(at: usize, message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            at,
        }
    }
}

impl fmt::Display for FilterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} (at character {})", self.message, self.at + 1)
    }
}

impl std::error::Error for FilterError {}

type PResult<T> = Result<T, FilterError>;

// ---------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Tok {
    /// A dotted identifier: a field name, a protocol name, or a bareword
    /// value. Which it is depends on position, resolved by the parser.
    Ident(String),
    Number(i128),
    /// A quoted string. Always a value, never a field.
    Str(String),
    Ip(IpAddr),
    /// An address with a prefix length: `10.0.0.0/24`.
    Cidr(IpAddr, u8),
    Mac([u8; 6]),
    Op(CmpOp),
    And,
    Or,
    Not,
    LParen,
    RParen,
    LBrace,
    RBrace,
    Comma,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    Gt,
    Ge,
    Lt,
    Le,
    Contains,
    In,
}

impl CmpOp {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Eq => "==",
            Self::Ne => "!=",
            Self::Gt => ">",
            Self::Ge => ">=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Contains => "contains",
            Self::In => "in",
        }
    }
}

#[derive(Debug, Clone)]
struct Spanned {
    tok: Tok,
    at: usize,
}

// ---------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------

/// A parsed filter value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Num(i128),
    Str(String),
    Ip(IpAddr),
    /// Network address plus prefix length. Compared with `==` this means
    /// "inside this network", which is what an engineer means by
    /// `ip.src == 10.0.0.0/8`.
    Cidr(IpAddr, u8),
    Mac([u8; 6]),
    Set(Vec<Value>),
}

/// A parsed filter expression.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// `tcp`, `dns` — "this protocol is present".
    Protocol(crate::dissect::Proto),
    /// `dns.qry.name` on its own — "this field exists in this packet".
    Present(String),
    Compare {
        field: String,
        op: CmpOp,
        value: Value,
        /// Position of the field token, for error reporting after the
        /// parse succeeds but registry lookup fails.
        at: usize,
    },
    Not(Box<Expr>),
    And(Box<Expr>, Box<Expr>),
    Or(Box<Expr>, Box<Expr>),
}

/// Parse a filter expression.
pub fn parse(input: &str) -> PResult<Expr> {
    let tokens = tokenize(input)?;
    if tokens.is_empty() {
        return Err(FilterError::new(0, "the filter is empty"));
    }
    let mut p = Parser { tokens, pos: 0 };
    let expr = p.parse_or()?;
    if let Some(extra) = p.peek() {
        return Err(FilterError::new(
            extra.at,
            "unexpected trailing input — did you mean to join these with `and`?",
        ));
    }
    Ok(expr)
}

// ---------------------------------------------------------------------
// Tokenizer
// ---------------------------------------------------------------------

fn tokenize(input: &str) -> PResult<Vec<Spanned>> {
    let b = input.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;

    while i < b.len() {
        let start = i;
        // Decode the character at `i` properly. Slicing on byte indices
        // without doing this panics the moment a filter contains a
        // multi-byte character — and filters carry hostnames, so
        // `dns.qry.name contains münchen` is an ordinary input, not an
        // exotic one.
        let c = input[i..].chars().next().unwrap_or('\u{fffd}');
        let c_len = c.len_utf8();

        if c.is_whitespace() {
            i += c_len;
            continue;
        }

        // Punctuation and operators. `get` rather than a slice, so a
        // two-byte window that would land inside a character is simply
        // not a match.
        let two = input.get(i..i + 2).unwrap_or("");
        let simple = match (c, two) {
            (_, "==") => Some((Tok::Op(CmpOp::Eq), 2)),
            (_, "!=") => Some((Tok::Op(CmpOp::Ne), 2)),
            (_, ">=") => Some((Tok::Op(CmpOp::Ge), 2)),
            (_, "<=") => Some((Tok::Op(CmpOp::Le), 2)),
            (_, "&&") => Some((Tok::And, 2)),
            (_, "||") => Some((Tok::Or, 2)),
            ('=', _) => Some((Tok::Op(CmpOp::Eq), 1)),
            ('>', _) => Some((Tok::Op(CmpOp::Gt), 1)),
            ('<', _) => Some((Tok::Op(CmpOp::Lt), 1)),
            ('!', _) => Some((Tok::Not, 1)),
            ('(', _) => Some((Tok::LParen, 1)),
            (')', _) => Some((Tok::RParen, 1)),
            ('{', _) => Some((Tok::LBrace, 1)),
            ('}', _) => Some((Tok::RBrace, 1)),
            (',', _) => Some((Tok::Comma, 1)),
            _ => None,
        };
        if let Some((tok, len)) = simple {
            out.push(Spanned { tok, at: start });
            i += len;
            continue;
        }

        // Quoted string. Backslash escapes the next character so a value
        // can contain a quote.
        if c == '"' || c == '\'' {
            let quote = c;
            i += c_len;
            let mut s = String::new();
            let mut closed = false;
            // Character-wise throughout. Advancing by bytes here — in
            // particular skipping two bytes past a backslash — lands
            // inside a multi-byte character and panics the next slice,
            // and a quoted string is exactly where a hostname with an
            // accent ends up.
            while i < b.len() {
                let Some(ch) = input[i..].chars().next() else {
                    break;
                };
                if ch == '\\' {
                    i += ch.len_utf8();
                    if let Some(esc) = input[i..].chars().next() {
                        s.push(esc);
                        i += esc.len_utf8();
                    }
                    continue;
                }
                if ch == quote {
                    i += ch.len_utf8();
                    closed = true;
                    break;
                }
                s.push(ch);
                i += ch.len_utf8();
            }
            if !closed {
                return Err(FilterError::new(start, "unterminated quoted string"));
            }
            out.push(Spanned {
                tok: Tok::Str(s),
                at: start,
            });
            continue;
        }

        // A bareword: identifier, number, IP, CIDR, or MAC. Scanned as one
        // run of "word characters" and then classified, because
        // `10.0.0.1`, `aa:bb:cc:dd:ee:ff` and `tcp.port` all look like
        // words until you inspect them.
        if is_word_char(c) {
            for ch in input[i..].chars() {
                if !is_word_char(ch) {
                    break;
                }
                i += ch.len_utf8();
            }
            let word = &input[start..i];
            out.push(Spanned {
                tok: classify_word(word, start)?,
                at: start,
            });
            continue;
        }

        return Err(FilterError::new(
            start,
            format!("unexpected character `{c}`"),
        ));
    }

    Ok(out)
}

/// Characters that may appear in an unquoted word.
///
/// `is_alphanumeric` rather than `is_ascii_alphanumeric` so an
/// internationalized hostname works unquoted — `dns.qry.name contains
/// münchen` is an ordinary filter, and requiring quotes around it would
/// be a papercut with no upside. Field names are all ASCII, so widening
/// this only affects values.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '.' | '_' | ':' | '-' | '/' | '*')
}

/// Decide what a bareword is.
///
/// Order matters: the most specific shapes are tried first, so
/// `10.0.0.0/24` is a CIDR rather than an identifier containing a slash.
fn classify_word(word: &str, at: usize) -> PResult<Tok> {
    match word.to_ascii_lowercase().as_str() {
        "and" => return Ok(Tok::And),
        "or" => return Ok(Tok::Or),
        "not" => return Ok(Tok::Not),
        "contains" => return Ok(Tok::Op(CmpOp::Contains)),
        "in" => return Ok(Tok::Op(CmpOp::In)),
        _ => {}
    }

    if let Some((net, prefix)) = word.split_once('/') {
        if let (Ok(ip), Ok(bits)) = (net.parse::<IpAddr>(), prefix.parse::<u8>()) {
            let max = if ip.is_ipv4() { 32 } else { 128 };
            if bits > max {
                return Err(FilterError::new(
                    at,
                    format!("a /{bits} prefix is too long for this address family"),
                ));
            }
            return Ok(Tok::Cidr(ip, bits));
        }
    }
    if let Ok(ip) = word.parse::<IpAddr>() {
        return Ok(Tok::Ip(ip));
    }
    if let Some(mac) = parse_mac(word) {
        return Ok(Tok::Mac(mac));
    }
    // Numbers: decimal, hex (`0x1f`), and float-looking values rounded to
    // microseconds so `frame.time_delta > 0.5` works without a float type
    // in the comparison layer.
    if let Some(hex) = word.strip_prefix("0x").or_else(|| word.strip_prefix("0X")) {
        if let Ok(n) = i128::from_str_radix(hex, 16) {
            return Ok(Tok::Number(n));
        }
    }
    if let Ok(n) = word.parse::<i128>() {
        return Ok(Tok::Number(n));
    }
    if let Ok(f) = word.parse::<f64>() {
        // Seconds → microseconds. Every duration field in the registry is
        // stored in microseconds, so this keeps `> 0.5` meaning half a
        // second rather than half a microsecond.
        return Ok(Tok::Number((f * 1_000_000.0).round() as i128));
    }

    Ok(Tok::Ident(word.to_string()))
}

fn parse_mac(word: &str) -> Option<[u8; 6]> {
    let sep = if word.contains(':') {
        ':'
    } else if word.matches('-').count() == 5 {
        '-'
    } else {
        return None;
    };
    let parts: Vec<&str> = word.split(sep).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.len() != 2 {
            return None;
        }
        mac[i] = u8::from_str_radix(p, 16).ok()?;
    }
    Some(mac)
}

// ---------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------

struct Parser {
    tokens: Vec<Spanned>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Spanned> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Spanned> {
        let t = self.tokens.get(self.pos).cloned();
        if t.is_some() {
            self.pos += 1;
        }
        t
    }

    fn eat(&mut self, want: &Tok) -> bool {
        if self.peek().map(|s| &s.tok) == Some(want) {
            self.pos += 1;
            true
        } else {
            false
        }
    }

    /// Position to report an error at when we ran out of input.
    fn end_at(&self) -> usize {
        self.tokens.last().map(|t| t.at).unwrap_or(0)
    }

    fn parse_or(&mut self) -> PResult<Expr> {
        let mut lhs = self.parse_and()?;
        while self.eat(&Tok::Or) {
            let rhs = self.parse_and()?;
            lhs = Expr::Or(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> PResult<Expr> {
        let mut lhs = self.parse_unary()?;
        while self.eat(&Tok::And) {
            let rhs = self.parse_unary()?;
            lhs = Expr::And(Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> PResult<Expr> {
        if self.eat(&Tok::Not) {
            return Ok(Expr::Not(Box::new(self.parse_unary()?)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> PResult<Expr> {
        let Some(tok) = self.next() else {
            return Err(FilterError::new(
                self.end_at(),
                "the filter ends where a term was expected",
            ));
        };

        match tok.tok {
            Tok::LParen => {
                let inner = self.parse_or()?;
                if !self.eat(&Tok::RParen) {
                    return Err(FilterError::new(tok.at, "unclosed `(`"));
                }
                Ok(inner)
            }
            Tok::Ident(name) => {
                // Is a comparison operator next?
                if let Some(Spanned {
                    tok: Tok::Op(op), ..
                }) = self.peek().cloned()
                {
                    self.pos += 1;
                    let value = self.parse_value(op)?;
                    return Ok(Expr::Compare {
                        field: name,
                        op,
                        value,
                        at: tok.at,
                    });
                }
                // Bare: a protocol name, or "this field is present".
                if let Some(p) = crate::dissect::Proto::from_tag(&name.to_ascii_lowercase()) {
                    Ok(Expr::Protocol(p))
                } else {
                    Ok(Expr::Present(name))
                }
            }
            other => Err(FilterError::new(
                tok.at,
                format!("expected a field name here, found {}", describe(&other)),
            )),
        }
    }

    fn parse_value(&mut self, op: CmpOp) -> PResult<Value> {
        if op == CmpOp::In {
            let Some(open) = self.next() else {
                return Err(FilterError::new(
                    self.end_at(),
                    "`in` needs a set, like `{80, 443}`",
                ));
            };
            if open.tok != Tok::LBrace {
                return Err(FilterError::new(
                    open.at,
                    "`in` needs a set in braces, like `in {80, 443}`",
                ));
            }
            let mut items = Vec::new();
            loop {
                if self.eat(&Tok::RBrace) {
                    break;
                }
                items.push(self.parse_scalar()?);
                if self.eat(&Tok::Comma) {
                    continue;
                }
                if self.eat(&Tok::RBrace) {
                    break;
                }
                return Err(FilterError::new(
                    self.peek().map(|s| s.at).unwrap_or_else(|| self.end_at()),
                    "expected `,` or `}` in a set",
                ));
            }
            if items.is_empty() {
                return Err(FilterError::new(open.at, "an `in` set cannot be empty"));
            }
            return Ok(Value::Set(items));
        }
        self.parse_scalar()
    }

    fn parse_scalar(&mut self) -> PResult<Value> {
        let Some(tok) = self.next() else {
            return Err(FilterError::new(
                self.end_at(),
                "the filter ends where a value was expected",
            ));
        };
        Ok(match tok.tok {
            Tok::Number(n) => Value::Num(n),
            Tok::Str(s) => Value::Str(s),
            Tok::Ip(ip) => Value::Ip(ip),
            Tok::Cidr(ip, bits) => Value::Cidr(ip, bits),
            Tok::Mac(m) => Value::Mac(m),
            // A bareword value: `dns.qry.name contains example` and
            // `tcp.flags.syn == true` both land here.
            Tok::Ident(w) => match w.to_ascii_lowercase().as_str() {
                "true" | "yes" => Value::Num(1),
                "false" | "no" => Value::Num(0),
                _ => Value::Str(w),
            },
            other => {
                return Err(FilterError::new(
                    tok.at,
                    format!("expected a value here, found {}", describe(&other)),
                ))
            }
        })
    }
}

fn describe(t: &Tok) -> String {
    match t {
        Tok::Ident(s) => format!("`{s}`"),
        Tok::Number(n) => format!("the number {n}"),
        Tok::Str(s) => format!("the text \"{s}\""),
        Tok::Ip(ip) => format!("the address {ip}"),
        Tok::Cidr(ip, b) => format!("the network {ip}/{b}"),
        Tok::Mac(_) => "a MAC address".into(),
        Tok::Op(o) => format!("`{}`", o.as_str()),
        Tok::And => "`and`".into(),
        Tok::Or => "`or`".into(),
        Tok::Not => "`not`".into(),
        Tok::LParen => "`(`".into(),
        Tok::RParen => "`)`".into(),
        Tok::LBrace => "`{`".into(),
        Tok::RBrace => "`}`".into(),
        Tok::Comma => "`,`".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dissect::Proto;

    fn p(s: &str) -> Expr {
        parse(s).unwrap_or_else(|e| panic!("{s:?} failed to parse: {e}"))
    }

    #[test]
    fn a_bare_protocol_name_is_a_presence_test() {
        assert_eq!(p("tcp"), Expr::Protocol(Proto::Tcp));
        assert_eq!(p("dns"), Expr::Protocol(Proto::Dns));
        assert_eq!(p("DNS"), Expr::Protocol(Proto::Dns), "case-insensitive");
    }

    #[test]
    fn a_bare_unknown_field_is_a_field_presence_test() {
        assert_eq!(p("dns.qry.name"), Expr::Present("dns.qry.name".to_string()));
    }

    #[test]
    fn comparisons_parse_with_their_value_types() {
        assert_eq!(
            p("tcp.port == 443"),
            Expr::Compare {
                field: "tcp.port".into(),
                op: CmpOp::Eq,
                value: Value::Num(443),
                at: 0
            }
        );
        assert!(matches!(
            p("ip.src == 10.0.0.1"),
            Expr::Compare {
                value: Value::Ip(_),
                ..
            }
        ));
        assert!(matches!(
            p("ip.src == 10.0.0.0/24"),
            Expr::Compare {
                value: Value::Cidr(_, 24),
                ..
            }
        ));
        assert!(matches!(
            p("eth.src == aa:bb:cc:dd:ee:ff"),
            Expr::Compare {
                value: Value::Mac(_),
                ..
            }
        ));
        assert!(matches!(
            p("http.host == \"api.internal\""),
            Expr::Compare {
                value: Value::Str(_),
                ..
            }
        ));
    }

    #[test]
    fn and_binds_tighter_than_or() {
        // a or b and c  ==  a or (b and c)
        let e = p("arp or tcp and udp");
        match e {
            Expr::Or(l, r) => {
                assert_eq!(*l, Expr::Protocol(Proto::Arp));
                assert!(matches!(*r, Expr::And(_, _)));
            }
            other => panic!("expected an Or at the root, got {other:?}"),
        }
    }

    #[test]
    fn parentheses_override_precedence() {
        let e = p("(arp or tcp) and udp");
        assert!(matches!(e, Expr::And(_, _)));
    }

    #[test]
    fn not_applies_to_the_next_term_only() {
        let e = p("not tcp and udp");
        match e {
            Expr::And(l, _) => assert!(matches!(*l, Expr::Not(_))),
            other => panic!("expected And(Not(tcp), udp), got {other:?}"),
        }
    }

    #[test]
    fn c_style_operators_are_accepted_as_aliases() {
        assert_eq!(p("tcp && udp"), p("tcp and udp"));
        assert_eq!(p("tcp || udp"), p("tcp or udp"));
        assert_eq!(p("!tcp"), p("not tcp"));
    }

    #[test]
    fn a_set_membership_test_parses() {
        match p("vlan.id in {10, 20, 30}") {
            Expr::Compare {
                op: CmpOp::In,
                value: Value::Set(items),
                ..
            } => assert_eq!(items.len(), 3),
            other => panic!("got {other:?}"),
        }
    }

    #[test]
    fn hex_and_seconds_values_convert() {
        assert!(matches!(
            p("eth.type == 0x0800"),
            Expr::Compare {
                value: Value::Num(2048),
                ..
            }
        ));
        // Durations are stored in microseconds, so half a second is
        // 500,000 — otherwise `> 0.5` would mean half a microsecond and
        // match everything.
        assert!(matches!(
            p("frame.time_delta > 0.5"),
            Expr::Compare {
                value: Value::Num(500_000),
                ..
            }
        ));
    }

    #[test]
    fn quoted_strings_keep_their_spaces_and_escapes() {
        match p(r#"http.user_agent contains "Mozilla 5.0""#) {
            Expr::Compare {
                value: Value::Str(s),
                ..
            } => assert_eq!(s, "Mozilla 5.0"),
            other => panic!("got {other:?}"),
        }
        match p(r#"http.host == "say \"hi\"""#) {
            Expr::Compare {
                value: Value::Str(s),
                ..
            } => assert_eq!(s, r#"say "hi""#),
            other => panic!("got {other:?}"),
        }
    }

    /// Filters carry hostnames, and hostnames are not ASCII. Every one of
    /// these panicked the first version of the tokenizer, which advanced
    /// by bytes: a two-byte operator window landing mid-character, a
    /// backslash escape skipping two bytes into the middle of one, and a
    /// bareword scan that refused non-ASCII outright.
    #[test]
    fn multi_byte_characters_do_not_break_the_tokenizer() {
        match p("dns.qry.name contains münchen") {
            Expr::Compare {
                value: Value::Str(s),
                ..
            } => assert_eq!(s, "münchen"),
            other => panic!("got {other:?}"),
        }
        match p(r#"http.host == "café.example.com""#) {
            Expr::Compare {
                value: Value::Str(s),
                ..
            } => assert_eq!(s, "café.example.com"),
            other => panic!("got {other:?}"),
        }
        match p(r#"http.host == "emoji \🚀 escaped""#) {
            Expr::Compare {
                value: Value::Str(s),
                ..
            } => assert_eq!(s, "emoji 🚀 escaped"),
            other => panic!("got {other:?}"),
        }
        // An unterminated string that ends mid-character must error, not
        // panic.
        assert!(parse("http.host == \"münch").is_err());
    }

    #[test]
    fn errors_point_at_the_offending_character() {
        let e = parse("tcp.port ==").unwrap_err();
        assert!(e.message.contains("value was expected"), "{}", e.message);

        let e = parse("(tcp and udp").unwrap_err();
        assert_eq!(e.at, 0, "the unclosed paren is at 0");

        let e = parse("tcp.port == 443 udp").unwrap_err();
        assert_eq!(e.at, 16, "the stray token starts at 16");
        assert!(
            e.message.contains("and"),
            "the message should suggest a fix"
        );

        let e = parse("tcp.port == \"unterminated").unwrap_err();
        assert!(e.message.contains("unterminated"));

        let e = parse("").unwrap_err();
        assert!(e.message.contains("empty"));

        let e = parse("ip.src == 10.0.0.0/99").unwrap_err();
        assert!(e.message.contains("too long"), "{}", e.message);
    }

    #[test]
    fn a_set_must_not_be_empty() {
        assert!(parse("tcp.port in {}").is_err());
        assert!(parse("tcp.port in 443").is_err());
    }

    /// The parser is fed strings a user types AND strings a model
    /// proposes while reasoning about untrusted packet contents. No input
    /// may panic or hang it.
    #[test]
    fn arbitrary_input_never_panics() {
        proptest::proptest!(|(s: String)| {
            let _ = parse(&s);
        });
    }

    #[test]
    fn deeply_nested_parentheses_do_not_blow_the_stack() {
        // Recursive descent recurses on nesting depth. A pathological
        // filter must fail gracefully rather than abort the process.
        let deep = format!("{}tcp{}", "(".repeat(200), ")".repeat(200));
        let _ = parse(&deep);
    }
}
