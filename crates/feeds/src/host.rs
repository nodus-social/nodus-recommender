//! Hostname validation for outbound instance requests.
//!
//! Every host name accepted from a caller (`X-Instance-Host`, `POST /api/v1/browse`,
//! `/s/{instance}/{status}`) is interpolated into an `https://{host}/…` URL or stored
//! for the calculator to crawl later. Accepting bare internal names, reserved
//! suffixes, ports, or IP literals would turn the API or calculator into an SSRF
//! primitive, so every entry point uses [`is_plausible_host`].

use std::net::IpAddr;

/// Reserved or internal host suffixes that must never be contacted as fediverse
/// instances.
const RESERVED_SUFFIXES: &[&str] = &[
    ".localhost",
    ".local",
    ".internal",
    ".svc",
    ".cluster.local",
    ".localdomain",
    ".arpa",
];

/// Return whether `host` is a syntactically valid, non-internal public FQDN.
///
/// Rejects empty strings, hosts longer than 253 bytes, ports (`:`), schemes, paths,
/// userinfo (`@`), whitespace, IPv4/IPv6 literals (including short/octal/hex IPv4
/// forms), single-label names (missing `.`), trailing/leading/repeated dots, labels
/// with invalid characters or leading/trailing hyphens, and reserved/internal
/// hostnames or suffixes (`localhost`, `.localhost`, `.local`, `.internal`, `.svc`,
/// `.cluster.local`, `.localdomain`, `.arpa`).
pub fn is_plausible_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }

    let lower = host.to_ascii_lowercase();
    if lower == "localhost"
        || RESERVED_SUFFIXES
            .iter()
            .any(|suffix| lower.ends_with(suffix))
    {
        return false;
    }

    let mut label_count = 0usize;
    let mut last_label = "";
    for label in lower.split('.') {
        if !is_valid_label(label) {
            return false;
        }
        last_label = label;
        label_count += 1;
    }

    if label_count < 2 || last_label.len() < 2 {
        return false;
    }

    // Public DNS TLDs cannot be purely numeric (blocks dotted/short/octal IPv4
    // literals), and at least one label must be non-numeric (blocks hex IPv4
    // literals such as `0x7f.0.0.0x1`).
    if last_label.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    if lower.split('.').all(is_numeric_ipv4_label) {
        return false;
    }

    true
}

fn is_valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

fn is_numeric_ipv4_label(label: &str) -> bool {
    if let Some(hex) = label.strip_prefix("0x") {
        !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
    } else {
        label.bytes().all(|b| b.is_ascii_digit())
    }
}

#[cfg(test)]
mod tests {
    use super::is_plausible_host;

    #[test]
    fn accepts_public_fqdns() {
        for host in [
            "mastodon.social",
            "Mastodon.Social",
            "social.example.org",
            "social.example.co.uk",
            "a.example",
            "my-instance.example.net",
            "xn--bcher-kva.example",
            "123.example",
            "sub1.sub2.mastodon.online",
        ] {
            assert!(is_plausible_host(host), "expected valid host: {host}");
        }
    }

    #[test]
    fn rejects_ports_schemes_paths_and_userinfo() {
        for host in [
            "localhost:3000",
            "localhost:8080",
            "mastodon.social:443",
            "evil.example:8080",
            "calculator.nodus.svc:8080",
            "127.0.0.1:6379",
            "127.0.0.1:6379/internal",
            "https://mastodon.social",
            "http://evil.example",
            "mastodon.social/api/v1",
            "user@evil.example",
            "evil example",
            " mastodon.social",
            "mastodon.social ",
            "evil.example?foo=bar",
            "evil.example#frag",
        ] {
            assert!(!is_plausible_host(host), "expected rejected host: {host}");
        }
    }

    #[test]
    fn rejects_ip_literals_and_private_ranges() {
        for host in [
            "127.0.0.1",
            "127.0.1.1",
            "127.1",
            "0177.0.0.1",
            "0x7f.0.0.1",
            "0x7f.0.0.0x1",
            "127.0.0.0x1",
            "169.254.169.254",
            "169.254.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "8.8.8.8",
            "::1",
            "[::1]",
            "[fe80::1]",
            "[::ffff:127.0.0.1]",
            "[2001:db8::1]",
        ] {
            assert!(!is_plausible_host(host), "expected rejected IP: {host}");
        }
    }

    #[test]
    fn rejects_single_label_and_reserved_internal_suffixes() {
        for host in [
            "localhost",
            "LOCALHOST",
            "api.localhost",
            "foo.bar.LOCALHOST",
            "redis",
            "calculator",
            "printer.local",
            "my-host.LOCAL",
            "metadata.google.internal",
            "host.docker.internal",
            "db.INTERNAL",
            "redis.nodus.svc",
            "calculator.nodus.SVC",
            "redis.default.svc.cluster.local",
            "api.cluster.local",
            "box.localdomain",
            "router.home.arpa",
        ] {
            assert!(
                !is_plausible_host(host),
                "expected rejected internal host: {host}"
            );
        }
    }

    #[test]
    fn rejects_malformed_labels_and_lengths() {
        let long_label = format!("{}.example", "a".repeat(64));
        let long_host = format!(
            "{}.{}.{}.{}.com",
            "a".repeat(60),
            "b".repeat(60),
            "c".repeat(60),
            "d".repeat(65)
        );
        for host in [
            "",
            ".",
            "..",
            ".mastodon.social",
            "mastodon.social.",
            "mastodon..social",
            "-evil.example",
            "evil-.example",
            "evil.-example",
            "evil.example-",
            "example.a",
            long_label.as_str(),
            long_host.as_str(),
        ] {
            assert!(
                !is_plausible_host(host),
                "expected rejected malformed host: {host}"
            );
        }
    }
}
