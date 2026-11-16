//! The query language: one small language for rule search, event filters, Explorer pivots and alert conditions.
//!
//! ```text
//! exe:*/curl host:*.example.com -port:443
//! (action:deny OR action:reject) time>-1h bytes>10M
//! firefox user:1000
//! ```
//!
//! Terms are `key:value` (or `key>value`, `key>=value`, `key<value`, `key<=value` for numbers and times), joined by
//! whitespace (and) or `OR`, negated with a leading `-`, grouped with parentheses; a value can be quoted. A bare word
//! is free text. A value with `*` or `?` is a glob over the whole value; without, it matches anywhere in it. Text
//! matches ignore case.
//!
//! [`parse`] gives the syntax tree, with each term's place in the text so a client can highlight it ([`tokens`] gives
//! the classified tokens for that). [`EventFilter::compile`] checks it against the event keys; the filter then runs
//! in memory ([`EventFilter::matches`]) or as SQL ([`EventFilter::sql`]), whose matching functions call back into the
//! same code ([`glob`], [`text`], [`in_net`]) so both always agree. [`RuleFilter`] does the same for rules, in memory
//! only (clients hold every rule).

use std::fmt::Write as _;
use std::net::IpAddr;
use std::ops::Range;

use ipnet::IpNet;

/// A comparison in a term.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cmp {
    /// `key:value`
    Is,
    Lt,
    Le,
    Gt,
    Ge,
}

impl Cmp {
    fn holds<T: PartialOrd>(self, left: &T, right: &T) -> bool {
        match self {
            Self::Is => left == right,
            Self::Lt => left < right,
            Self::Le => left <= right,
            Self::Gt => left > right,
            Self::Ge => left >= right,
        }
    }

    fn sql(self) -> &'static str {
        match self {
            Self::Is => "=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
        }
    }
}

/// A query's syntax tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    /// Matches everything: the empty query.
    All,
    And(Vec<Expr>),
    Or(Vec<Expr>),
    Not(Box<Expr>),
    /// Free text.
    Text {
        value: String,
        span: Range<usize>,
    },
    Term {
        key: String,
        cmp: Cmp,
        value: String,
        span: Range<usize>,
    },
}

/// What is wrong with a query, and where.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct QueryError {
    pub message: String,
    /// Byte offsets into the query.
    pub span: Range<usize>,
}

fn error(message: impl Into<String>, span: Range<usize>) -> QueryError {
    QueryError {
        message: message.into(),
        span,
    }
}

/// What a token is, for highlighting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenKind {
    Key,
    /// `:`, `<`, `>=`…
    Operator,
    Value,
    Text,
    /// `OR`, `-`, parentheses.
    Syntax,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Lexeme {
    Open,
    Close,
    Or,
    Not,
    /// A word or a term: its key, comparison and value (unquoted); the offsets of the key's end and the value's start.
    Word {
        key: Option<(String, Cmp)>,
        value: String,
        key_end: usize,
        value_start: usize,
    },
}

#[derive(Debug, Clone)]
struct Token {
    lexeme: Lexeme,
    span: Range<usize>,
}

/// The keys a term can have, in either kind of query.
const KEYS: [&str; 22] = [
    "exe", "host", "ip", "port", "proto", "user", "action", "rule", "bytes", "sent", "received",
    "time", "context", "name", "folder", "tier", "enabled", "locked", "app", "cmdline", "parent",
    "notes",
];

fn lex(query: &str) -> Result<Vec<Token>, QueryError> {
    let bytes = query.as_bytes();
    let mut tokens = Vec::new();
    let mut i = 0;
    while let Some(&c) = bytes.get(i) {
        // Any whitespace separates, as the word reader stops at any: a no-break space is no word.
        if let Some(space) = query
            .get(i..)
            .and_then(|rest| rest.chars().next())
            .filter(|c| c.is_whitespace())
        {
            i += space.len_utf8();
            continue;
        }
        match c {
            b'(' => {
                tokens.push(Token {
                    lexeme: Lexeme::Open,
                    span: i..i + 1,
                });
                i += 1;
            }
            b')' => {
                tokens.push(Token {
                    lexeme: Lexeme::Close,
                    span: i..i + 1,
                });
                i += 1;
            }
            b'-' if i + 1 < bytes.len()
                && !matches!(bytes.get(i + 1), Some(b' ' | b'\t' | b'\n' | b'\r' | b')')) =>
            {
                tokens.push(Token {
                    lexeme: Lexeme::Not,
                    span: i..i + 1,
                });
                i += 1;
            }
            _ => {
                let start = i;
                let (token, end) = word(query, start)?;
                if end <= start {
                    // Never stand still: a character no rule reads ends the query with an error.
                    return Err(error("unexpected character", start..start + 1));
                }
                tokens.push(token);
                i = end;
            }
        }
    }
    Ok(tokens)
}

/// A word starting at `start`: a term, free text or `OR`. Returns it and where it ends.
fn word(query: &str, start: usize) -> Result<(Token, usize), QueryError> {
    let bytes = query.as_bytes();
    // The key: letters up to an operator.
    let mut i = start;
    while bytes.get(i).is_some_and(u8::is_ascii_alphabetic) {
        i += 1;
    }
    let candidate = query.get(start..i).unwrap_or("").to_ascii_lowercase();
    let operator = match (bytes.get(i), bytes.get(i + 1)) {
        (Some(b':'), _) => Some((Cmp::Is, 1)),
        (Some(b'<'), Some(b'=')) => Some((Cmp::Le, 2)),
        (Some(b'>'), Some(b'=')) => Some((Cmp::Ge, 2)),
        (Some(b'<'), _) => Some((Cmp::Lt, 1)),
        (Some(b'>'), _) => Some((Cmp::Gt, 1)),
        _ => None,
    };
    let (key, key_end, value_start) = match operator {
        Some((cmp, len)) if i > start => (Some((candidate, cmp)), i, i + len),
        _ => (None, start, start),
    };
    let (value, end) = value(query, value_start)?;
    if key.is_none() && value == "OR" && end - start == 2 {
        return Ok((
            Token {
                lexeme: Lexeme::Or,
                span: start..end,
            },
            end,
        ));
    }
    Ok((
        Token {
            lexeme: Lexeme::Word {
                key,
                value,
                key_end,
                value_start,
            },
            span: start..end,
        },
        end,
    ))
}

/// A value at `start`, quoted or up to whitespace or a closing parenthesis. Returns it and where it ends.
fn value(query: &str, start: usize) -> Result<(String, usize), QueryError> {
    let bytes = query.as_bytes();
    if bytes.get(start) == Some(&b'"') {
        let mut value = String::new();
        let mut chars = query.get(start + 1..).unwrap_or("").char_indices();
        while let Some((offset, c)) = chars.next() {
            match c {
                '"' => return Ok((value, start + 1 + offset + 1)),
                '\\' => match chars.next() {
                    Some((_, escaped)) => value.push(escaped),
                    None => break,
                },
                c => value.push(c),
            }
        }
        return Err(error("unclosed quote", start..query.len()));
    }
    let rest = query.get(start..).unwrap_or("");
    let end = rest
        .find(|c: char| c.is_whitespace() || c == ')' || c == '(')
        .map_or(query.len(), |offset| start + offset);
    Ok((query.get(start..end).unwrap_or("").to_owned(), end))
}

/// The tokens of `query`, classified for highlighting. A query that doesn't lex gives the tokens before the error.
#[must_use]
pub fn tokens(query: &str) -> Vec<(Range<usize>, TokenKind)> {
    let mut out = Vec::new();
    let lexed = lex(query).unwrap_or_else(|e| {
        // Everything before the error, then the rest as text.
        let mut head = lex(query.get(..e.span.start).unwrap_or("")).unwrap_or_default();
        head.push(Token {
            lexeme: Lexeme::Word {
                key: None,
                value: String::new(),
                key_end: e.span.start,
                value_start: e.span.start,
            },
            span: e.span,
        });
        head
    });
    for token in lexed {
        match token.lexeme {
            Lexeme::Open | Lexeme::Close | Lexeme::Or | Lexeme::Not => {
                out.push((token.span, TokenKind::Syntax));
            }
            Lexeme::Word {
                key: Some(_),
                key_end,
                value_start,
                ..
            } => {
                out.push((token.span.start..key_end, TokenKind::Key));
                out.push((key_end..value_start, TokenKind::Operator));
                if value_start < token.span.end {
                    out.push((value_start..token.span.end, TokenKind::Value));
                }
            }
            Lexeme::Word { key: None, .. } => out.push((token.span, TokenKind::Text)),
        }
    }
    out
}

/// Parses a query. Unknown keys are left for the compile step, which knows which apply.
pub fn parse(query: &str) -> Result<Expr, QueryError> {
    let tokens = lex(query)?;
    let mut parser = Parser {
        tokens: &tokens,
        at: 0,
        end: query.len(),
        depth: 0,
    };
    let expr = parser.or()?;
    match parser.tokens.get(parser.at) {
        None => Ok(expr),
        Some(token) => Err(error("unmatched `)`", token.span.clone())),
    }
}

/// Nesting allowed: queries are typed by people, and the parser recurses.
const MAX_DEPTH: usize = 32;

struct Parser<'a> {
    tokens: &'a [Token],
    at: usize,
    end: usize,
    depth: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.at)
    }

    fn or(&mut self) -> Result<Expr, QueryError> {
        let mut any = vec![self.and()?];
        while let Some(Token {
            lexeme: Lexeme::Or,
            span,
        }) = self.peek()
        {
            let span = span.clone();
            self.at += 1;
            let next = self.and()?;
            if next == Expr::All {
                return Err(error("`OR` needs something after it", span));
            }
            any.push(next);
        }
        Ok(if any.len() == 1 {
            any.pop().unwrap_or(Expr::All)
        } else {
            Expr::Or(any)
        })
    }

    fn and(&mut self) -> Result<Expr, QueryError> {
        let mut all = Vec::new();
        while let Some(token) = self.peek() {
            if matches!(token.lexeme, Lexeme::Or | Lexeme::Close) {
                break;
            }
            all.push(self.unary()?);
        }
        Ok(match all.len() {
            0 => Expr::All,
            1 => all.pop().unwrap_or(Expr::All),
            _ => Expr::And(all),
        })
    }

    fn unary(&mut self) -> Result<Expr, QueryError> {
        let Some(token) = self.peek().cloned() else {
            return Err(error("expected a term", self.end..self.end));
        };
        self.at += 1;
        match token.lexeme {
            Lexeme::Not => {
                self.depth += 1;
                if self.depth > MAX_DEPTH {
                    return Err(error("too deeply nested", token.span));
                }
                let inner = self.unary()?;
                self.depth -= 1;
                Ok(Expr::Not(Box::new(inner)))
            }
            Lexeme::Open => {
                self.depth += 1;
                if self.depth > MAX_DEPTH {
                    return Err(error("too deeply nested", token.span));
                }
                let inner = self.or()?;
                self.depth -= 1;
                match self.peek() {
                    Some(Token {
                        lexeme: Lexeme::Close,
                        ..
                    }) => {
                        self.at += 1;
                        if inner == Expr::All {
                            return Err(error("empty parentheses", token.span));
                        }
                        Ok(inner)
                    }
                    _ => Err(error("unclosed `(`", token.span)),
                }
            }
            Lexeme::Word {
                key: Some((key, cmp)),
                value,
                ..
            } => Ok(Expr::Term {
                key,
                cmp,
                value,
                span: token.span,
            }),
            Lexeme::Word {
                key: None, value, ..
            } => Ok(Expr::Text {
                value,
                span: token.span,
            }),
            Lexeme::Or | Lexeme::Close => Err(error("expected a term", token.span)),
        }
    }
}

/// Whether `pattern` matches `value`: with `*` (any run) or `?` (one character), as a glob over the whole value;
/// otherwise anywhere in it. Case is ignored.
#[must_use]
pub fn glob(pattern: &str, value: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let value = value.to_lowercase();
    if !pattern.contains(['*', '?']) {
        return value.contains(&pattern);
    }
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    // Iterative glob with backtracking to the last star: linear in practice, no recursion.
    let (mut pi, mut vi) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while vi < v.len() {
        match p.get(pi) {
            Some('*') => {
                star = Some((pi, vi));
                pi += 1;
            }
            Some('?') => {
                pi += 1;
                vi += 1;
            }
            Some(c) if Some(c) == v.get(vi) => {
                pi += 1;
                vi += 1;
            }
            _ => match star {
                Some((sp, sv)) => {
                    pi = sp + 1;
                    vi = sv + 1;
                    star = Some((sp, sv + 1));
                }
                None => return false,
            },
        }
    }
    p.get(pi..)
        .is_some_and(|rest| rest.iter().all(|c| *c == '*'))
}

/// Free text: in any of `fields`.
#[must_use]
pub fn text(needle: &str, fields: &[&str]) -> bool {
    fields.iter().any(|field| glob(needle, field))
}

/// Whether `address` is in `net`.
#[must_use]
pub fn in_net(net: &IpNet, address: IpAddr) -> bool {
    let address = match address {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(address, IpAddr::V4),
        v4 @ IpAddr::V4(_) => v4,
    };
    net.contains(&address)
}

/// An event as the filter sees it.
#[derive(Debug, Clone, Copy)]
pub struct EventView<'a> {
    pub time_ms: u64,
    pub exe: &'a str,
    /// Empty: no name.
    pub host: &'a str,
    pub address: IpAddr,
    pub port: u16,
    pub protocol: u8,
    pub uid: u32,
    /// The protocol's `Action` number.
    pub action: u8,
    /// 0: none.
    pub rule: u64,
    /// The protocol's `Context` number less one: 0 host, 1 container, 2 VM, 3 network namespace.
    pub context: u8,
    pub bytes_out: u64,
    pub bytes_in: u64,
}

#[derive(Debug, Clone, PartialEq)]
enum EventCond {
    Exe(String),
    Host(String),
    NoHost,
    Net(IpNet),
    Port(Cmp, u16),
    PortRange(u16, u16),
    Protocol(u8),
    Uid(Cmp, u32),
    Action(u8),
    Rule(u64),
    Bytes(Cmp, u64),
    Sent(Cmp, u64),
    Received(Cmp, u64),
    Time(Cmp, u64),
    Context(u8),
    Text(String),
}

#[derive(Debug, Clone, PartialEq)]
enum Node<C> {
    All,
    And(Vec<Node<C>>),
    Or(Vec<Node<C>>),
    Not(Box<Node<C>>),
    Cond(C),
}

impl<C> Node<C> {
    fn eval(&self, cond: &impl Fn(&C) -> bool) -> bool {
        match self {
            Self::All => true,
            Self::And(all) => all.iter().all(|n| n.eval(cond)),
            Self::Or(any) => any.iter().any(|n| n.eval(cond)),
            Self::Not(inner) => !inner.eval(cond),
            Self::Cond(c) => cond(c),
        }
    }
}

/// What a query compiles against: the time now (for `time>-1h`) and user names.
pub struct Context<'a> {
    pub now_ms: u64,
    /// A user name's uid.
    pub uid_of: &'a dyn Fn(&str) -> Option<u32>,
}

/// A compiled event filter.
#[derive(Debug, Clone, PartialEq)]
pub struct EventFilter(Node<EventCond>);

/// A value for SQL's bound parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqlValue {
    Int(i64),
    Text(String),
}

impl EventFilter {
    /// Compiles a parsed query for events.
    pub fn compile(expr: &Expr, cx: &Context<'_>) -> Result<Self, QueryError> {
        compile(
            expr,
            &|key, cmp, value, span| event_cond(key, cmp, value, span, cx),
            &|v| EventCond::Text(v.to_owned()),
        )
        .map(Self)
    }

    /// Parses and compiles.
    pub fn parse(query: &str, cx: &Context<'_>) -> Result<Self, QueryError> {
        Self::compile(&parse(query)?, cx)
    }

    /// Whether it lets every event through.
    #[must_use]
    pub fn is_all(&self) -> bool {
        self.0 == Node::All
    }

    #[must_use]
    pub fn matches(&self, event: &EventView<'_>) -> bool {
        self.0.eval(&|c| event_matches(c, event))
    }

    /// The filter as an SQL condition with `?` parameters, over columns `e.*` and the exe's and host's strings as
    /// `x.value` and `h.value` (NULL: no host). It calls `snitchhiker_glob(pattern, value)`,
    /// `snitchhiker_text(needle, exe, host)` and `snitchhiker_net(net, address)`, which the database registers from
    /// [`glob`], [`text`] and [`in_net`]; `e.address` is the 16-byte address (IPv4 mapped).
    #[must_use]
    pub fn sql(&self) -> (String, Vec<SqlValue>) {
        let mut sql = String::new();
        let mut values = Vec::new();
        node_sql(&self.0, &mut sql, &mut values);
        (sql, values)
    }
}

fn node_sql(node: &Node<EventCond>, sql: &mut String, values: &mut Vec<SqlValue>) {
    let join =
        |nodes: &[Node<EventCond>], op: &str, sql: &mut String, values: &mut Vec<SqlValue>| {
            sql.push('(');
            for (i, n) in nodes.iter().enumerate() {
                if i > 0 {
                    sql.push_str(op);
                }
                node_sql(n, sql, values);
            }
            sql.push(')');
        };
    match node {
        Node::All => sql.push('1'),
        Node::And(all) => join(all, " AND ", sql, values),
        Node::Or(any) => join(any, " OR ", sql, values),
        Node::Not(inner) => {
            sql.push_str("NOT ");
            node_sql(inner, sql, values);
        }
        Node::Cond(c) => cond_sql(c, sql, values),
    }
}

fn int(value: impl TryInto<i64>) -> SqlValue {
    SqlValue::Int(value.try_into().unwrap_or(i64::MAX))
}

fn cond_sql(c: &EventCond, sql: &mut String, values: &mut Vec<SqlValue>) {
    let mut cmp = |column: &str, cmp: Cmp, value: SqlValue| {
        let _ = write!(sql, "{column} {} ?", cmp.sql());
        values.push(value);
    };
    match c {
        EventCond::Exe(p) => {
            sql.push_str("snitchhiker_glob(?, x.value)");
            values.push(SqlValue::Text(p.clone()));
        }
        EventCond::Host(p) => {
            sql.push_str("coalesce(snitchhiker_glob(?, h.value), 0)");
            values.push(SqlValue::Text(p.clone()));
        }
        EventCond::NoHost => sql.push_str("h.value IS NULL"),
        EventCond::Net(net) => {
            sql.push_str("snitchhiker_net(?, e.address)");
            values.push(SqlValue::Text(net.to_string()));
        }
        EventCond::Port(c, port) => cmp("e.port", *c, int(*port)),
        EventCond::PortRange(low, high) => {
            sql.push_str("e.port BETWEEN ? AND ?");
            values.push(int(*low));
            values.push(int(*high));
        }
        EventCond::Protocol(p) => cmp("e.protocol", Cmp::Is, int(*p)),
        EventCond::Uid(c, uid) => cmp("e.uid", *c, int(*uid)),
        EventCond::Action(a) => cmp("e.action", Cmp::Is, int(*a)),
        EventCond::Rule(0) => sql.push_str("e.rule IS NULL"),
        // Null-safe: a condition must never be NULL, or a `NOT` around it would drop the event as well.
        EventCond::Rule(r) => {
            sql.push_str("e.rule IS ?");
            values.push(int(*r));
        }
        EventCond::Bytes(c, b) => cmp("(e.bytes_out + e.bytes_in)", *c, int(*b)),
        EventCond::Sent(c, b) => cmp("e.bytes_out", *c, int(*b)),
        EventCond::Received(c, b) => cmp("e.bytes_in", *c, int(*b)),
        EventCond::Time(c, t) => cmp("e.time_ms", *c, int(*t)),
        EventCond::Context(k) => cmp("e.context", Cmp::Is, int(*k)),
        EventCond::Text(t) => {
            sql.push_str("snitchhiker_text(?, x.value, h.value)");
            values.push(SqlValue::Text(t.clone()));
        }
    }
}

fn event_matches(c: &EventCond, e: &EventView<'_>) -> bool {
    match c {
        EventCond::Exe(p) => glob(p, e.exe),
        EventCond::Host(p) => !e.host.is_empty() && glob(p, e.host),
        EventCond::NoHost => e.host.is_empty(),
        EventCond::Net(net) => in_net(net, e.address),
        EventCond::Port(c, port) => c.holds(&e.port, port),
        EventCond::PortRange(low, high) => (*low..=*high).contains(&e.port),
        EventCond::Protocol(p) => e.protocol == *p,
        EventCond::Uid(c, uid) => c.holds(&e.uid, uid),
        EventCond::Action(a) => e.action == *a,
        EventCond::Rule(r) => e.rule == *r,
        EventCond::Bytes(c, b) => c.holds(&e.bytes_out.saturating_add(e.bytes_in), b),
        EventCond::Sent(c, b) => c.holds(&e.bytes_out, b),
        EventCond::Received(c, b) => c.holds(&e.bytes_in, b),
        EventCond::Time(c, t) => c.holds(&e.time_ms, t),
        EventCond::Context(k) => e.context == *k,
        EventCond::Text(t) => text(t, &[e.exe, e.host]),
    }
}

type Leaf<'a, C> = dyn Fn(&str, Cmp, &str, &Range<usize>) -> Result<C, QueryError> + 'a;

fn compile<C>(
    expr: &Expr,
    leaf: &Leaf<'_, C>,
    free: &dyn Fn(&str) -> C,
) -> Result<Node<C>, QueryError> {
    Ok(match expr {
        Expr::All => Node::All,
        Expr::And(all) => Node::And(
            all.iter()
                .map(|e| compile(e, leaf, free))
                .collect::<Result<_, _>>()?,
        ),
        Expr::Or(any) => Node::Or(
            any.iter()
                .map(|e| compile(e, leaf, free))
                .collect::<Result<_, _>>()?,
        ),
        Expr::Not(inner) => Node::Not(Box::new(compile(inner, leaf, free)?)),
        Expr::Text { value, .. } => Node::Cond(free(value)),
        Expr::Term {
            key,
            cmp,
            value,
            span,
        } => Node::Cond(leaf(key, *cmp, value, span)?),
    })
}

fn only_is(key: &str, cmp: Cmp, span: &Range<usize>) -> Result<(), QueryError> {
    if cmp == Cmp::Is {
        Ok(())
    } else {
        Err(error(format!("`{key}` takes `{key}:value`"), span.clone()))
    }
}

fn unknown(key: &str, span: &Range<usize>, keys: &str) -> QueryError {
    if KEYS.contains(&key) {
        error(
            format!("`{key}` doesn't apply here (keys: {keys})"),
            span.clone(),
        )
    } else {
        error(format!("unknown key `{key}` (keys: {keys})"), span.clone())
    }
}

const EVENT_KEYS: &str =
    "exe, host, ip, port, proto, user, action, rule, bytes, sent, received, time, context";

fn event_cond(
    key: &str,
    cmp: Cmp,
    value: &str,
    span: &Range<usize>,
    cx: &Context<'_>,
) -> Result<EventCond, QueryError> {
    let bad = |what: &str| error(format!("`{value}` isn't {what}"), span.clone());
    Ok(match key {
        "exe" => {
            only_is(key, cmp, span)?;
            EventCond::Exe(value.to_owned())
        }
        "host" => {
            only_is(key, cmp, span)?;
            if value.is_empty() || value == "none" {
                EventCond::NoHost
            } else {
                EventCond::Host(value.to_owned())
            }
        }
        "ip" => {
            only_is(key, cmp, span)?;
            let net = value
                .parse::<IpNet>()
                .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
                .map_err(|_| bad("an address or network"))?;
            EventCond::Net(net)
        }
        "port" => match value.split_once('-') {
            Some((low, high)) if cmp == Cmp::Is => {
                let low = low.parse().map_err(|_| bad("a port range"))?;
                let high = high.parse().map_err(|_| bad("a port range"))?;
                EventCond::PortRange(low, high)
            }
            _ => EventCond::Port(cmp, value.parse().map_err(|_| bad("a port"))?),
        },
        "proto" => {
            only_is(key, cmp, span)?;
            EventCond::Protocol(protocol(value).ok_or_else(|| bad("a protocol"))?)
        }
        "user" => EventCond::Uid(
            cmp,
            value
                .parse()
                .ok()
                .or_else(|| (cx.uid_of)(value))
                .ok_or_else(|| bad("a user"))?,
        ),
        "action" => {
            only_is(key, cmp, span)?;
            EventCond::Action(match value.to_ascii_lowercase().as_str() {
                "allow" => 1,
                "deny" => 2,
                "reject" => 3,
                _ => return Err(bad("an action (allow, deny, reject)")),
            })
        }
        "rule" => {
            only_is(key, cmp, span)?;
            if value == "none" {
                EventCond::Rule(0)
            } else {
                EventCond::Rule(value.parse().map_err(|_| bad("a rule id or `none`"))?)
            }
        }
        "bytes" => EventCond::Bytes(cmp, size(value).ok_or_else(|| bad("a size"))?),
        "sent" => EventCond::Sent(cmp, size(value).ok_or_else(|| bad("a size"))?),
        "received" => EventCond::Received(cmp, size(value).ok_or_else(|| bad("a size"))?),
        "time" => EventCond::Time(
            cmp,
            time(value, cx.now_ms)
                .ok_or_else(|| bad("a time (-1h, 2026-11-15, 2026-11-15T10:00)"))?,
        ),
        "context" => {
            only_is(key, cmp, span)?;
            EventCond::Context(
                context(value).ok_or_else(|| bad("a context (host, container, vm, netns)"))?,
            )
        }
        _ => return Err(unknown(key, span, EVENT_KEYS)),
    })
}

fn protocol(value: &str) -> Option<u8> {
    match value.to_ascii_lowercase().as_str() {
        "tcp" => Some(6),
        "udp" => Some(17),
        "udplite" => Some(136),
        "sctp" => Some(132),
        "icmp" => Some(1),
        "icmpv6" => Some(58),
        n => n.parse().ok(),
    }
}

fn context(value: &str) -> Option<u8> {
    match value.to_ascii_lowercase().as_str() {
        "host" => Some(0),
        "container" => Some(1),
        "vm" => Some(2),
        "netns" => Some(3),
        _ => None,
    }
}

/// `10M`, `512k`, `1G`, `100` (bytes; binary multiples).
fn size(value: &str) -> Option<u64> {
    let lower = value.to_ascii_lowercase();
    let lower = lower.trim_end_matches('b').trim_end_matches('i');
    let multiple = match lower.chars().last()? {
        'k' => 1u64 << 10,
        'm' => 1 << 20,
        'g' => 1 << 30,
        't' => 1 << 40,
        _ => 1,
    };
    let number = if multiple == 1 {
        lower
    } else {
        lower.get(..lower.len() - 1)?
    };
    number.parse::<u64>().ok()?.checked_mul(multiple)
}

/// `-1h` (relative to now: s, m, h, d, w), `2026-11-15`, `2026-11-15T10:00[:00]` (UTC), or Unix ms.
fn time(value: &str, now_ms: u64) -> Option<u64> {
    if let Some(ago) = value.strip_prefix('-') {
        let unit = ago.chars().last()?;
        let number: u64 = ago.get(..ago.len() - unit.len_utf8())?.parse().ok()?;
        let ms = match unit {
            's' => 1_000,
            'm' => 60_000,
            'h' => 3_600_000,
            'd' => 86_400_000,
            'w' => 7 * 86_400_000,
            _ => return None,
        };
        return Some(now_ms.saturating_sub(number.checked_mul(ms)?));
    }
    if value.bytes().all(|b| b.is_ascii_digit()) {
        return value.parse().ok();
    }
    let (date, clock) = value.split_once('T').unwrap_or((value, "00:00"));
    let mut d = date.split('-').map(str::parse::<i64>);
    let (year, month, day) = (d.next()?.ok()?, d.next()?.ok()?, d.next()?.ok()?);
    if d.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut c = clock.split(':').map(str::parse::<i64>);
    let (hour, minute) = (c.next()?.ok()?, c.next()?.ok()?);
    let second = c.next().transpose().ok()?.unwrap_or(0);
    if !(0..24).contains(&hour) || !(0..60).contains(&minute) || !(0..60).contains(&second) {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let seconds = days * 86_400 + hour * 3_600 + minute * 60 + second;
    u64::try_from(seconds).ok()?.checked_mul(1_000)
}

/// Days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let yoe = year - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A rule as the filter sees it.
#[derive(Debug, Clone)]
pub struct RuleView<'a> {
    pub name: &'a str,
    pub notes: &'a str,
    /// `Apps/curl`: the folders it is in.
    pub folder: &'a str,
    /// The protocol's `Action` number.
    pub action: u8,
    /// `override`, `normal` or `fallback`.
    pub tier: &'a str,
    pub enabled: bool,
    pub locked: bool,
    pub exe: &'a [String],
    pub app: &'a [String],
    pub cmdline: &'a [String],
    pub parent: &'a [String],
    pub host: &'a [String],
    pub net: &'a [String],
    pub port: &'a [String],
    pub protocol: &'a [String],
    pub uid: &'a [u32],
}

#[derive(Debug, Clone, PartialEq)]
enum RuleCond {
    Name(String),
    Notes(String),
    Folder(String),
    Action(u8),
    Tier(String),
    Enabled(bool),
    Locked(bool),
    /// A pattern over one of the condition lists: which, and the text searched for.
    List(&'static str, String),
    Uid(u32),
    Text(String),
}

/// A compiled rule filter.
#[derive(Debug, Clone, PartialEq)]
pub struct RuleFilter(Node<RuleCond>);

const RULE_KEYS: &str = "name, notes, folder, action, tier, enabled, locked, exe, app, cmdline, parent, host, ip, port, proto, user";

impl RuleFilter {
    /// Compiles a parsed query for rules.
    pub fn compile(expr: &Expr, cx: &Context<'_>) -> Result<Self, QueryError> {
        compile(
            expr,
            &|key, cmp, value, span| rule_cond(key, cmp, value, span, cx),
            &|v| RuleCond::Text(v.to_owned()),
        )
        .map(Self)
    }

    pub fn parse(query: &str, cx: &Context<'_>) -> Result<Self, QueryError> {
        Self::compile(&parse(query)?, cx)
    }

    #[must_use]
    pub fn matches(&self, rule: &RuleView<'_>) -> bool {
        self.0.eval(&|c| rule_matches(c, rule))
    }
}

fn boolean(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "yes" | "true" | "on" => Some(true),
        "no" | "false" | "off" => Some(false),
        _ => None,
    }
}

fn rule_cond(
    key: &str,
    cmp: Cmp,
    value: &str,
    span: &Range<usize>,
    cx: &Context<'_>,
) -> Result<RuleCond, QueryError> {
    only_is(key, cmp, span)?;
    let bad = |what: &str| error(format!("`{value}` isn't {what}"), span.clone());
    let owned = value.to_owned();
    Ok(match key {
        "name" => RuleCond::Name(owned),
        "notes" => RuleCond::Notes(owned),
        "folder" => RuleCond::Folder(owned),
        "action" => RuleCond::Action(match value.to_ascii_lowercase().as_str() {
            "allow" => 1,
            "deny" => 2,
            "reject" => 3,
            _ => return Err(bad("an action (allow, deny, reject)")),
        }),
        "tier" => match value.to_ascii_lowercase().as_str() {
            t @ ("override" | "normal" | "fallback") => RuleCond::Tier(t.to_owned()),
            _ => return Err(bad("a tier (override, normal, fallback)")),
        },
        "enabled" => RuleCond::Enabled(boolean(value).ok_or_else(|| bad("yes or no"))?),
        "locked" => RuleCond::Locked(boolean(value).ok_or_else(|| bad("yes or no"))?),
        "exe" => RuleCond::List("exe", owned),
        "app" => RuleCond::List("app", owned),
        "cmdline" => RuleCond::List("cmdline", owned),
        "parent" => RuleCond::List("parent", owned),
        "host" => RuleCond::List("host", owned),
        "ip" => RuleCond::List("net", owned),
        "port" => RuleCond::List("port", owned),
        "proto" => RuleCond::List("protocol", owned),
        "user" => RuleCond::Uid(
            value
                .parse()
                .ok()
                .or_else(|| (cx.uid_of)(value))
                .ok_or_else(|| bad("a user"))?,
        ),
        _ => return Err(unknown(key, span, RULE_KEYS)),
    })
}

fn rule_matches(c: &RuleCond, r: &RuleView<'_>) -> bool {
    let list = |which: &str| -> &[String] {
        match which {
            "exe" => r.exe,
            "app" => r.app,
            "cmdline" => r.cmdline,
            "parent" => r.parent,
            "host" => r.host,
            "net" => r.net,
            "port" => r.port,
            _ => r.protocol,
        }
    };
    match c {
        RuleCond::Name(p) => glob(p, r.name),
        RuleCond::Notes(p) => glob(p, r.notes),
        RuleCond::Folder(p) => glob(p, r.folder),
        RuleCond::Action(a) => r.action == *a,
        RuleCond::Tier(t) => r.tier == t,
        RuleCond::Enabled(e) => r.enabled == *e,
        RuleCond::Locked(l) => r.locked == *l,
        RuleCond::List(which, p) => list(which).iter().any(|v| glob(p, v)),
        RuleCond::Uid(uid) => r.uid.contains(uid),
        RuleCond::Text(t) => {
            text(t, &[r.name, r.notes, r.folder])
                || [r.exe, r.app, r.host, r.cmdline, r.parent]
                    .iter()
                    .any(|l| l.iter().any(|v| glob(t, v)))
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn any_whitespace_separates_and_lexing_always_ends() {
        // A no-break space and other Unicode spaces made the lexer loop for ever.
        for query in [
            "exe:curl\u{a0}port:443",
            "\u{a0}",
            "\u{2028}x",
            "a\u{3000}b",
        ] {
            let lexed = lex(query).unwrap();
            assert!(lexed.len() <= 2, "{query:?}: {}", lexed.len());
        }
        assert!(parse("exe:curl\u{a0}port:443").is_ok());
    }

    use super::*;

    fn cx() -> Context<'static> {
        Context {
            now_ms: 10 * 3_600_000,
            uid_of: &|name| (name == "alice").then_some(1000),
        }
    }

    fn event() -> EventView<'static> {
        EventView {
            time_ms: 9 * 3_600_000 + 1,
            exe: "/usr/bin/curl",
            host: "api.example.com",
            address: "93.184.216.34".parse().unwrap(),
            port: 443,
            protocol: 6,
            uid: 1000,
            action: 1,
            rule: 7,
            context: 0,
            bytes_out: 2048,
            bytes_in: 20 << 20,
        }
    }

    fn hits(query: &str) -> bool {
        EventFilter::parse(query, &cx()).unwrap().matches(&event())
    }

    #[test]
    fn terms_match_events() {
        for query in [
            "",
            "curl",
            "exe:curl",
            "exe:*/curl",
            "host:*.example.com",
            "ip:93.184.0.0/16",
            "port:443",
            "port:400-500",
            "port>=443",
            "proto:tcp",
            "user:alice",
            "user:1000",
            "action:allow",
            "rule:7",
            "bytes>10M",
            "received>=20M",
            "sent<4k",
            "time>-1h",
            "time<1970-01-02",
            "context:host",
            "-action:deny",
            "action:deny OR port:443",
            "(action:deny OR action:reject) OR curl",
            "EXAMPLE",
        ] {
            assert!(hits(query), "{query} should match");
        }
        for query in [
            "firefox",
            "exe:curl*",
            "host:none",
            "ip:10.0.0.0/8",
            "port:80",
            "port>443",
            "proto:udp",
            "user:0",
            "action:deny",
            "rule:none",
            "bytes>1G",
            "time>-30m",
            "context:container",
            "-curl",
            "curl -port:443",
            "action:deny OR port:80",
        ] {
            assert!(!hits(query), "{query} shouldn't match");
        }
    }

    #[test]
    fn mistakes_say_where_they_are() {
        let e = EventFilter::parse("exe:curl colour:red", &cx()).unwrap_err();
        assert_eq!(e.span, 9..19);
        assert!(e.message.contains("unknown key"));
        let e = EventFilter::parse("name:x", &cx()).unwrap_err();
        assert!(e.message.contains("doesn't apply"));
        assert_eq!(parse("(port:1").unwrap_err().span, 0..1);
        assert_eq!(parse("port:1)").unwrap_err().span, 6..7);
        assert_eq!(parse("exe:\"a b").unwrap_err().message, "unclosed quote");
        assert!(parse("a OR").is_err());
        assert!(parse("()").is_err());
        assert!(EventFilter::parse("port:http", &cx()).is_err());
        assert!(EventFilter::parse("exe>3", &cx()).is_err());
    }

    #[test]
    fn quotes_and_negation_parse() {
        assert_eq!(
            parse("-exe:\"/opt/My App/bin\" OR x").unwrap(),
            Expr::Or(vec![
                Expr::Not(Box::new(Expr::Term {
                    key: "exe".to_owned(),
                    cmp: Cmp::Is,
                    value: "/opt/My App/bin".to_owned(),
                    span: 1..22,
                })),
                Expr::Text {
                    value: "x".to_owned(),
                    span: 26..27,
                },
            ])
        );
        // A lone dash is text, not negation.
        assert_eq!(
            parse("a - b").unwrap(),
            Expr::And(vec![
                Expr::Text {
                    value: "a".to_owned(),
                    span: 0..1
                },
                Expr::Text {
                    value: "-".to_owned(),
                    span: 2..3
                },
                Expr::Text {
                    value: "b".to_owned(),
                    span: 4..5
                },
            ])
        );
    }

    #[test]
    fn tokens_classify_for_highlighting() {
        assert_eq!(
            tokens("-port>=443 OR (curl)"),
            vec![
                (0..1, TokenKind::Syntax),
                (1..5, TokenKind::Key),
                (5..7, TokenKind::Operator),
                (7..10, TokenKind::Value),
                (11..13, TokenKind::Syntax),
                (14..15, TokenKind::Syntax),
                (15..19, TokenKind::Text),
                (19..20, TokenKind::Syntax),
            ]
        );
        // An unclosed quote highlights what comes before it.
        assert_eq!(tokens("a \"b").first(), Some(&(0..1, TokenKind::Text)));
    }

    #[test]
    fn globs_and_times() {
        assert!(glob("*.example.com", "a.b.example.com"));
        assert!(!glob("*.example.com", "example.com"));
        assert!(glob("/usr/bin/python3.?", "/usr/bin/python3.1"));
        assert!(glob("a*b*c", "aXXbYYc"));
        assert!(!glob("a*b*c", "aXXbYY"));
        assert!(glob("**", ""));
        assert_eq!(time("2026-11-15", 0), Some(1_794_700_800_000));
        assert_eq!(time("2026-11-15T10:00", 0), Some(1_794_736_800_000));
        assert_eq!(time("-2h", 3 * 3_600_000), Some(3_600_000));
        assert_eq!(time("2026-13-01", 0), None);
        assert_eq!(size("10M"), Some(10 << 20));
        assert_eq!(size("512KiB"), Some(512 << 10));
    }

    #[test]
    fn rules_are_searched() {
        let exe = vec!["/usr/bin/curl".to_owned()];
        let host = vec!["*.example.com".to_owned()];
        let rule = RuleView {
            name: "curl to example",
            notes: "",
            folder: "Apps/curl",
            action: 1,
            tier: "normal",
            enabled: true,
            locked: false,
            exe: &exe,
            app: &[],
            cmdline: &[],
            parent: &[],
            host: &host,
            net: &[],
            port: &[],
            protocol: &[],
            uid: &[1000],
        };
        let hits = |q: &str| RuleFilter::parse(q, &cx()).unwrap().matches(&rule);
        assert!(hits("curl"));
        assert!(hits("folder:apps/*"));
        assert!(hits("host:example.com enabled:yes action:allow user:alice"));
        assert!(!hits("locked:yes"));
        assert!(!hits("tier:override"));
        assert!(RuleFilter::parse("bytes>1", &cx()).is_err());
    }

    #[test]
    fn deep_nesting_is_refused_not_overflowed() {
        let deep = "(".repeat(10_000) + "a" + &")".repeat(10_000);
        assert!(parse(&deep).is_err());
        assert!(parse(&("-".repeat(10_000) + "a")).is_err());
    }

    #[test]
    fn sql_binds_every_value() {
        let filter =
            EventFilter::parse("exe:\"x'; DROP TABLE events;--\" port>1 -host:none", &cx())
                .unwrap();
        let (sql, values) = filter.sql();
        assert!(!sql.contains("DROP"));
        assert_eq!(
            sql,
            "(snitchhiker_glob(?, x.value) AND e.port > ? AND NOT h.value IS NULL)"
        );
        assert_eq!(values.len(), 2);
    }
}
