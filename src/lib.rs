// SPDX-License-Identifier: MIT OR Apache-2.0

//! # SigmaOS Domain Blocker
//!
//! Block domains system-wide by managing `/etc/hosts` entries. Inspired by
//! the Omarchy desktop philosophy, Hyprland's compositing aesthetics, and the
//! Catppuccin Mocha colour palette — clean, composable, and minimal by default.
//!
//! ## Features
//! - Blocklist management (add / remove / toggle individual domains)
//! - `/etc/hosts` file parsing and in-place editing (non-destructive)
//! - Category-based block groups: `Ads`, `Malware`, `Social`, `Custom`
//! - Whitelist / override support (whitelisted domains are never blocked)
//! - Pure `std` — no external crates required

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;

// ── Error types ──────────────────────────────────────────────────────────────

/// All errors produced by the domain blocker.
#[derive(Debug, PartialEq)]
pub enum BlockerError {
    /// The supplied domain name is syntactically invalid.
    InvalidDomain(String),
    /// The domain is on the whitelist and cannot be blocked.
    DomainWhitelisted(String),
    /// The domain was not found in the blocklist.
    DomainNotFound(String),
    /// A category with this name does not exist.
    CategoryNotFound(String),
    /// The `/etc/hosts` content could not be parsed.
    ParseError(String),
}

impl fmt::Display for BlockerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDomain(d) => write!(f, "invalid domain name: '{d}'"),
            Self::DomainWhitelisted(d) => write!(f, "domain is whitelisted and cannot be blocked: '{d}'"),
            Self::DomainNotFound(d) => write!(f, "domain not found in blocklist: '{d}'"),
            Self::CategoryNotFound(c) => write!(f, "category not found: '{c}'"),
            Self::ParseError(e) => write!(f, "hosts file parse error: {e}"),
        }
    }
}

impl std::error::Error for BlockerError {}

// ── Domain ───────────────────────────────────────────────────────────────────

/// A validated domain name.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Domain(String);

impl Domain {
    /// Create a `Domain`, returning `Err` if the name is not valid.
    pub fn new(raw: &str) -> Result<Self, BlockerError> {
        let s = raw.trim().to_ascii_lowercase();
        if s.is_empty() || s.len() > 253 {
            return Err(BlockerError::InvalidDomain(raw.to_string()));
        }
        for label in s.split('.') {
            if label.is_empty() || label.len() > 63 {
                return Err(BlockerError::InvalidDomain(raw.to_string()));
            }
            if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                return Err(BlockerError::InvalidDomain(raw.to_string()));
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(BlockerError::InvalidDomain(raw.to_string()));
            }
        }
        Ok(Self(s))
    }

    /// Return the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Domain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Category ─────────────────────────────────────────────────────────────────

/// Pre-defined categories of block groups.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Category {
    Ads,
    Malware,
    Social,
    Custom(String),
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ads => f.write_str("ads"),
            Self::Malware => f.write_str("malware"),
            Self::Social => f.write_str("social"),
            Self::Custom(n) => write!(f, "custom:{n}"),
        }
    }
}

impl Category {
    /// Parse from a string.  `"ads"`, `"malware"`, `"social"`, or any other
    /// value becomes `Custom(value)`.
    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "ads" => Self::Ads,
            "malware" => Self::Malware,
            "social" => Self::Social,
            other => Self::Custom(other.to_string()),
        }
    }
}

// ── BlockEntry ───────────────────────────────────────────────────────────────

/// A single entry in the blocklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEntry {
    pub domain: Domain,
    pub category: Category,
    pub enabled: bool,
}

impl BlockEntry {
    pub fn new(domain: Domain, category: Category) -> Self {
        Self { domain, category, enabled: true }
    }

    /// Generate the `/etc/hosts` line for this entry.
    pub fn hosts_line(&self) -> String {
        format!("0.0.0.0 {}", self.domain)
    }
}

// ── BlocklistConfig (builder) ─────────────────────────────────────────────────

/// Builder for configuring the blocker before construction.
#[derive(Debug, Default)]
pub struct BlocklistConfig {
    redirect_ip: Option<String>,
    marker_start: Option<String>,
    marker_end: Option<String>,
}

impl BlocklistConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// IP address to redirect blocked domains to (default `0.0.0.0`).
    pub fn redirect_ip(mut self, ip: &str) -> Self {
        self.redirect_ip = Some(ip.to_string());
        self
    }

    /// Custom begin-marker comment written into `/etc/hosts` (default `# BEGIN sigmaos-block`).
    pub fn marker_start(mut self, m: &str) -> Self {
        self.marker_start = Some(m.to_string());
        self
    }

    /// Custom end-marker comment (default `# END sigmaos-block`).
    pub fn marker_end(mut self, m: &str) -> Self {
        self.marker_end = Some(m.to_string());
        self
    }

    /// Finalise into a [`Blocklist`].
    pub fn build(self) -> Blocklist {
        Blocklist {
            entries: HashMap::new(),
            whitelist: HashSet::new(),
            redirect_ip: self.redirect_ip.unwrap_or_else(|| "0.0.0.0".to_string()),
            marker_start: self.marker_start
                .unwrap_or_else(|| "# BEGIN sigmaos-block".to_string()),
            marker_end: self.marker_end
                .unwrap_or_else(|| "# END sigmaos-block".to_string()),
        }
    }
}

// ── Blocklist ─────────────────────────────────────────────────────────────────

/// Central domain-blocker state.
#[derive(Debug)]
pub struct Blocklist {
    entries: HashMap<Domain, BlockEntry>,
    whitelist: HashSet<Domain>,
    pub redirect_ip: String,
    pub marker_start: String,
    pub marker_end: String,
}

impl Blocklist {
    /// Create with defaults.
    pub fn new() -> Self {
        BlocklistConfig::new().build()
    }

    // ── Whitelist management ──────────────────────────────────────────────

    /// Add a domain to the whitelist.  Whitelisted domains are excluded from
    /// the generated hosts block even if present in the blocklist.
    pub fn whitelist_add(&mut self, domain: Domain) {
        // If it was previously blocked, disable it automatically.
        if let Some(e) = self.entries.get_mut(&domain) {
            e.enabled = false;
        }
        self.whitelist.insert(domain);
    }

    /// Remove a domain from the whitelist.
    pub fn whitelist_remove(&mut self, domain: &Domain) -> bool {
        self.whitelist.remove(domain)
    }

    /// Check whether a domain is whitelisted.
    pub fn is_whitelisted(&self, domain: &Domain) -> bool {
        self.whitelist.contains(domain)
    }

    // ── Blocklist management ──────────────────────────────────────────────

    /// Add a domain to the blocklist under the given category.
    pub fn add(&mut self, domain: Domain, category: Category) -> Result<(), BlockerError> {
        if self.whitelist.contains(&domain) {
            return Err(BlockerError::DomainWhitelisted(domain.as_str().to_string()));
        }
        self.entries.insert(domain.clone(), BlockEntry::new(domain, category));
        Ok(())
    }

    /// Remove a domain from the blocklist entirely.
    pub fn remove(&mut self, domain: &Domain) -> Result<(), BlockerError> {
        self.entries
            .remove(domain)
            .map(|_| ())
            .ok_or_else(|| BlockerError::DomainNotFound(domain.as_str().to_string()))
    }

    /// Enable a previously-disabled blocklist entry.
    pub fn enable(&mut self, domain: &Domain) -> Result<(), BlockerError> {
        let entry = self.entries.get_mut(domain)
            .ok_or_else(|| BlockerError::DomainNotFound(domain.as_str().to_string()))?;
        entry.enabled = true;
        Ok(())
    }

    /// Disable (but keep) a blocklist entry.
    pub fn disable(&mut self, domain: &Domain) -> Result<(), BlockerError> {
        let entry = self.entries.get_mut(domain)
            .ok_or_else(|| BlockerError::DomainNotFound(domain.as_str().to_string()))?;
        entry.enabled = false;
        Ok(())
    }

    /// Toggle the enabled state of a domain.
    pub fn toggle(&mut self, domain: &Domain) -> Result<bool, BlockerError> {
        let entry = self.entries.get_mut(domain)
            .ok_or_else(|| BlockerError::DomainNotFound(domain.as_str().to_string()))?;
        entry.enabled = !entry.enabled;
        Ok(entry.enabled)
    }

    /// Return all entries belonging to a category (enabled or not).
    pub fn by_category(&self, category: &Category) -> Vec<&BlockEntry> {
        let mut v: Vec<&BlockEntry> = self.entries.values()
            .filter(|e| &e.category == category)
            .collect();
        v.sort_by(|a, b| a.domain.cmp(&b.domain));
        v
    }

    /// Number of entries (enabled + disabled).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    // ── /etc/hosts integration ────────────────────────────────────────────

    /// Generate the managed block-section to embed in `/etc/hosts`.
    pub fn generate_hosts_block(&self) -> String {
        let mut lines = vec![self.marker_start.clone()];
        let mut domains: Vec<&BlockEntry> = self.entries.values()
            .filter(|e| e.enabled && !self.whitelist.contains(&e.domain))
            .collect();
        domains.sort_by(|a, b| a.domain.cmp(&b.domain));
        for entry in domains {
            lines.push(format!("{} {}", self.redirect_ip, entry.domain));
        }
        lines.push(self.marker_end.clone());
        lines.join("\n")
    }

    /// Apply the block section into existing `/etc/hosts` content, replacing
    /// any previous managed block (idempotent).
    pub fn apply_to_hosts(&self, existing: &str) -> String {
        let block = self.generate_hosts_block();
        // Remove old managed block if present.
        let stripped = Self::strip_managed_block(existing, &self.marker_start, &self.marker_end);
        let trimmed = stripped.trim_end();
        if trimmed.is_empty() {
            block
        } else {
            format!("{trimmed}\n{block}")
        }
    }

    /// Remove the managed block from hosts content, leaving the rest intact.
    pub fn remove_from_hosts(&self, existing: &str) -> String {
        Self::strip_managed_block(existing, &self.marker_start, &self.marker_end)
    }

    fn strip_managed_block<'a>(content: &'a str, start: &str, end: &str) -> String {
        let mut result = Vec::new();
        let mut inside = false;
        for line in content.lines() {
            if line.trim() == start {
                inside = true;
                continue;
            }
            if line.trim() == end {
                inside = false;
                continue;
            }
            if !inside {
                result.push(line);
            }
        }
        result.join("\n")
    }

    /// Parse a hosts file and return the domains found inside the managed block.
    pub fn parse_managed_domains(&self, content: &str) -> Vec<Domain> {
        let mut found = Vec::new();
        let mut inside = false;
        for line in content.lines() {
            if line.trim() == self.marker_start {
                inside = true;
                continue;
            }
            if line.trim() == self.marker_end {
                break;
            }
            if inside {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(d) = Domain::new(parts[1]) {
                        found.push(d);
                    }
                }
            }
        }
        found
    }
}

impl Default for Blocklist {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // helper
    fn dom(s: &str) -> Domain {
        Domain::new(s).unwrap()
    }

    // ── Domain validation ─────────────────────────────────────────────────

    #[test]
    fn test_domain_valid_names() {
        // Arrange
        let cases = ["example.com", "ads.doubleclick.net", "sub-domain.io"];
        // Act + Assert
        for name in cases {
            assert!(Domain::new(name).is_ok(), "expected '{name}' to be valid");
        }
    }

    #[test]
    fn test_domain_invalid_names() {
        // Arrange
        let cases = ["", "-bad.com", "bad-.com", "has space.com", &"a".repeat(254)];
        // Act + Assert
        for name in cases {
            assert!(
                Domain::new(name).is_err(),
                "expected '{name}' to be invalid"
            );
        }
    }

    #[test]
    fn test_domain_normalises_case() {
        // Arrange / Act
        let d = Domain::new("ADS.Example.COM").unwrap();
        // Assert
        assert_eq!(d.as_str(), "ads.example.com");
    }

    // ── Blocklist management ──────────────────────────────────────────────

    #[test]
    fn test_add_and_remove_domain() {
        // Arrange
        let mut bl = Blocklist::new();
        let d = dom("tracker.example.com");
        // Act
        bl.add(d.clone(), Category::Ads).unwrap();
        assert_eq!(bl.len(), 1);
        bl.remove(&d).unwrap();
        // Assert
        assert_eq!(bl.len(), 0);
    }

    #[test]
    fn test_toggle_domain_state() {
        // Arrange
        let mut bl = Blocklist::new();
        let d = dom("social.example.com");
        bl.add(d.clone(), Category::Social).unwrap();
        // Act: toggle off
        let now_enabled = bl.toggle(&d).unwrap();
        // Assert
        assert!(!now_enabled);
        // Act: toggle back on
        let now_enabled = bl.toggle(&d).unwrap();
        assert!(now_enabled);
    }

    #[test]
    fn test_whitelist_prevents_adding() {
        // Arrange
        let mut bl = Blocklist::new();
        let d = dom("good.example.com");
        bl.whitelist_add(d.clone());
        // Act
        let result = bl.add(d.clone(), Category::Ads);
        // Assert
        assert_eq!(result, Err(BlockerError::DomainWhitelisted("good.example.com".to_string())));
    }

    #[test]
    fn test_whitelist_excludes_from_hosts_block() {
        // Arrange
        let mut bl = Blocklist::new();
        let blocked = dom("ads.evil.com");
        let safe = dom("safe.site.com");
        bl.add(blocked.clone(), Category::Ads).unwrap();
        // We manually insert 'safe' so we can whitelist it after the fact.
        bl.entries.insert(safe.clone(), BlockEntry::new(safe.clone(), Category::Ads));
        bl.whitelist_add(safe.clone());
        // Act
        let block = bl.generate_hosts_block();
        // Assert
        assert!(block.contains("ads.evil.com"));
        assert!(!block.contains("safe.site.com"));
    }

    #[test]
    fn test_by_category_filtering() {
        // Arrange
        let mut bl = Blocklist::new();
        bl.add(dom("ads1.com"), Category::Ads).unwrap();
        bl.add(dom("ads2.com"), Category::Ads).unwrap();
        bl.add(dom("malware.com"), Category::Malware).unwrap();
        // Act
        let ad_entries = bl.by_category(&Category::Ads);
        // Assert
        assert_eq!(ad_entries.len(), 2);
        assert!(ad_entries.iter().all(|e| e.category == Category::Ads));
    }

    // ── /etc/hosts round-trip ─────────────────────────────────────────────

    #[test]
    fn test_apply_to_hosts_inserts_block() {
        // Arrange
        let mut bl = Blocklist::new();
        bl.add(dom("evil.com"), Category::Malware).unwrap();
        let existing = "127.0.0.1 localhost\n::1 localhost";
        // Act
        let result = bl.apply_to_hosts(existing);
        // Assert
        assert!(result.contains("127.0.0.1 localhost"));
        assert!(result.contains("# BEGIN sigmaos-block"));
        assert!(result.contains("0.0.0.0 evil.com"));
        assert!(result.contains("# END sigmaos-block"));
    }

    #[test]
    fn test_apply_to_hosts_is_idempotent() {
        // Arrange
        let mut bl = Blocklist::new();
        bl.add(dom("evil.com"), Category::Malware).unwrap();
        let existing = "127.0.0.1 localhost";
        // Act: apply twice
        let once = bl.apply_to_hosts(existing);
        let twice = bl.apply_to_hosts(&once);
        // Assert: exactly one managed block
        assert_eq!(
            twice.matches("# BEGIN sigmaos-block").count(),
            1,
            "managed block should appear exactly once"
        );
    }

    #[test]
    fn test_remove_from_hosts_cleans_block() {
        // Arrange
        let mut bl = Blocklist::new();
        bl.add(dom("evil.com"), Category::Malware).unwrap();
        let existing = "127.0.0.1 localhost";
        let with_block = bl.apply_to_hosts(existing);
        // Act
        let cleaned = bl.remove_from_hosts(&with_block);
        // Assert
        assert!(!cleaned.contains("# BEGIN sigmaos-block"));
        assert!(!cleaned.contains("evil.com"));
        assert!(cleaned.contains("127.0.0.1 localhost"));
    }

    #[test]
    fn test_parse_managed_domains_roundtrip() {
        // Arrange
        let mut bl = Blocklist::new();
        bl.add(dom("alpha.com"), Category::Ads).unwrap();
        bl.add(dom("beta.com"), Category::Malware).unwrap();
        let hosts = bl.apply_to_hosts("127.0.0.1 localhost");
        // Act
        let mut parsed = bl.parse_managed_domains(&hosts);
        parsed.sort();
        // Assert
        assert_eq!(parsed, vec![dom("alpha.com"), dom("beta.com")]);
    }

    // ── Builder ───────────────────────────────────────────────────────────

    #[test]
    fn test_builder_custom_redirect_ip() {
        // Arrange / Act
        let bl = BlocklistConfig::new()
            .redirect_ip("127.0.0.1")
            .build();
        // Assert
        assert_eq!(bl.redirect_ip, "127.0.0.1");
    }

    // ── Category ─────────────────────────────────────────────────────────

    #[test]
    fn test_category_from_str() {
        // Arrange / Act / Assert
        assert_eq!(Category::from_str("ads"), Category::Ads);
        assert_eq!(Category::from_str("MALWARE"), Category::Malware);
        assert_eq!(Category::from_str("custom-list"), Category::Custom("custom-list".to_string()));
    }

    // ── Error display ─────────────────────────────────────────────────────

    #[test]
    fn test_error_display_messages() {
        // Arrange / Act / Assert
        let e = BlockerError::InvalidDomain("bad!".to_string());
        assert!(e.to_string().contains("bad!"));

        let e2 = BlockerError::DomainWhitelisted("ok.com".to_string());
        assert!(e2.to_string().contains("ok.com"));
    }
}
