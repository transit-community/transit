//! CSV importer — the universal escape hatch. Header-driven; `host` is
//! the only required column. Uses the `csv` crate for correct quoting /
//! embedded-comma / embedded-newline handling.
//!
//! Recognized headers (case-insensitive, any order): `host` (required),
//! `name`/`id`, `port`, `username`/`user`, `vendor`, `group`,
//! `key_path`/`identity_file`. Unknown columns are ignored.

use super::{expand_tilde, AuthKind, ImportError, ImportedConnection, ParsedImport};

pub fn parse_csv(text: &str) -> Result<ParsedImport, ImportError> {
    let mut reader = ::csv::ReaderBuilder::new()
        .trim(::csv::Trim::All)
        .flexible(true)
        .from_reader(text.as_bytes());

    let headers = reader
        .headers()
        .map_err(|e| ImportError::Csv(format!("could not read header row: {e}")))?
        .clone();
    let col = |name: &str| headers.iter().position(|h| h.eq_ignore_ascii_case(name));

    let host_idx =
        col("host").ok_or_else(|| ImportError::Csv("missing required `host` column".into()))?;
    let name_idx = col("name").or_else(|| col("id"));
    let port_idx = col("port");
    let user_idx = col("username").or_else(|| col("user"));
    let vendor_idx = col("vendor");
    let group_idx = col("group");
    let key_idx = col("key_path")
        .or_else(|| col("identity_file"))
        .or_else(|| col("identityfile"));

    let mut out = ParsedImport::default();
    for (i, record) in reader.records().enumerate() {
        let line = i + 2; // +1 header, +1 to 1-base
        let record = record.map_err(|e| ImportError::Csv(format!("row {line}: {e}")))?;
        let field = |idx: Option<usize>| {
            idx.and_then(|i| record.get(i))
                .map(str::trim)
                .filter(|s| !s.is_empty())
        };

        let host = match field(Some(host_idx)) {
            Some(h) => h.to_string(),
            None => {
                out.warnings.push(format!("row {line}: skipped (no host)"));
                continue;
            }
        };
        let key_path = field(key_idx).map(expand_tilde);
        let auth_kind = if key_path.is_some() {
            AuthKind::PublicKeyFile
        } else {
            AuthKind::Unknown
        };
        out.connections.push(ImportedConnection {
            source_name: field(name_idx).unwrap_or(&host).to_string(),
            host,
            port: field(port_idx).and_then(|p| p.parse().ok()).unwrap_or(22),
            username: field(user_idx).map(String::from),
            group_path: field(group_idx).map(String::from),
            jump_host: None,
            key_path,
            vendor_hint: field(vendor_idx).map(String::from),
            auth_kind,
            credential_link: None,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_and_minimal_rows() {
        let text = "name,host,port,username,vendor,group,key_path\n\
                    core,10.0.0.1,2222,netops,junos,Lab/Junos,/k/id\n\
                    ,10.0.0.2,,,,,\n";
        let out = parse_csv(text).unwrap();
        assert_eq!(out.connections.len(), 2);

        let a = &out.connections[0];
        assert_eq!(a.source_name, "core");
        assert_eq!(a.port, 2222);
        assert_eq!(a.username.as_deref(), Some("netops"));
        assert_eq!(a.vendor_hint.as_deref(), Some("junos"));
        assert_eq!(a.group_path.as_deref(), Some("Lab/Junos"));
        assert_eq!(a.auth_kind, AuthKind::PublicKeyFile);

        let b = &out.connections[1];
        assert_eq!(b.source_name, "10.0.0.2"); // falls back to host
        assert_eq!(b.port, 22);
        assert!(b.username.is_none());
        assert_eq!(b.auth_kind, AuthKind::Unknown);
    }

    #[test]
    fn honors_quoting_and_column_reorder() {
        let text = "host,group\n1.2.3.4,\"Prod, US/Core\"\n";
        let out = parse_csv(text).unwrap();
        assert_eq!(
            out.connections[0].group_path.as_deref(),
            Some("Prod, US/Core")
        );
    }

    #[test]
    fn missing_host_column_is_an_error() {
        let err = parse_csv("name,port\nx,22\n").unwrap_err();
        assert!(matches!(err, ImportError::Csv(_)));
    }

    #[test]
    fn rows_without_host_value_are_skipped_with_warning() {
        let out = parse_csv("host,name\n,orphan\n1.1.1.1,ok\n").unwrap();
        assert_eq!(out.connections.len(), 1);
        assert!(out.warnings.iter().any(|w| w.contains("no host")));
    }
}
