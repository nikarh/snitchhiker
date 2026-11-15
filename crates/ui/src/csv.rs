//! Tables as CSV (RFC 4180), for the clipboard.

/// One field: quoted when it holds a comma, a quote or a line break, with quotes doubled.
#[must_use]
pub fn field(text: &str) -> String {
    if text.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_owned()
    }
}

/// A table: the header and the rows, each line ending in CRLF.
#[must_use]
pub fn table(header: &[&str], rows: impl IntoIterator<Item = Vec<String>>) -> String {
    let mut text = header
        .iter()
        .map(|h| field(h))
        .collect::<Vec<_>>()
        .join(",");
    text.push_str("\r\n");
    for row in rows {
        text.push_str(&row.iter().map(|f| field(f)).collect::<Vec<_>>().join(","));
        text.push_str("\r\n");
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fields_are_quoted_when_they_need_it() {
        assert_eq!(field("curl"), "curl");
        assert_eq!(field("a,b"), "\"a,b\"");
        assert_eq!(field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(
            table(&["a", "b"], [vec!["1".to_owned(), "x,y".to_owned()]]),
            "a,b\r\n1,\"x,y\"\r\n"
        );
    }
}
