use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub const SETTINGS_FILE: &str = "settings.json";

/// User-tunable detection settings. Persisted as JSON in the app config dir.
/// Changes apply to the next Open File / Watch File.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", default)]
pub struct DetectionSettings {
    /// Failures (4xx / failed logins) from one IP within the window that trigger a rate alert.
    pub rate_threshold: u32,
    pub rate_window_secs: u32,
    /// Standard deviations from the running mean before a response size is flagged.
    pub baseline_sigma: f64,
    /// IPs or CIDR ranges (e.g. "10.0.0.0/8", "2001:db8::/32") that are never flagged.
    pub allowlist: Vec<String>,
}

impl Default for DetectionSettings {
    fn default() -> Self {
        Self {
            rate_threshold: 50,
            rate_window_secs: 10,
            baseline_sigma: 3.0,
            allowlist: Vec::new(),
        }
    }
}

impl DetectionSettings {
    /// Rejects values that would break detection, with a message fit for the UI.
    pub fn validate(&self) -> Result<(), String> {
        if !(2..=100_000).contains(&self.rate_threshold) {
            return Err("Rate threshold must be between 2 and 100000.".into());
        }
        if !(1..=3_600).contains(&self.rate_window_secs) {
            return Err("Rate window must be between 1 and 3600 seconds.".into());
        }
        if !(1.0..=10.0).contains(&self.baseline_sigma) {
            return Err("Baseline sigma must be between 1 and 10.".into());
        }
        for item in &self.allowlist {
            IpRange::parse(item).map_err(|e| format!("Allowlist entry '{item}': {e}"))?;
        }
        Ok(())
    }

    pub fn allowlist_ranges(&self) -> Vec<IpRange> {
        // validate() has already run on anything that reaches here; skip anything malformed
        self.allowlist.iter().filter_map(|s| IpRange::parse(s).ok()).collect()
    }

    /// Loads settings from `dir`, falling back to defaults if the file is missing or invalid.
    pub fn load(dir: &Path) -> Self {
        let path = dir.join(SETTINGS_FILE);
        let Ok(text) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        match serde_json::from_str::<Self>(&text) {
            Ok(s) if s.validate().is_ok() => s,
            Ok(_) | Err(_) => {
                log::warn!("Ignoring invalid settings file {}", path.display());
                Self::default()
            }
        }
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        self.validate()?;
        std::fs::create_dir_all(dir).map_err(|e| format!("Cannot create config folder: {e}"))?;
        let json = serde_json::to_string_pretty(self).map_err(|e| format!("Serialize error: {e}"))?;
        std::fs::write(dir.join(SETTINGS_FILE), json).map_err(|e| format!("Cannot save settings: {e}"))
    }
}

/// A single IP or a CIDR range, IPv4 or IPv6.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct IpRange {
    base: IpAddr,
    prefix: u8,
}

impl IpRange {
    pub fn parse(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let (addr, prefix) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let base: IpAddr = addr.parse().map_err(|_| "not a valid IP address".to_string())?;
        let max = if base.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|&p| p <= max)
                .ok_or_else(|| format!("prefix must be 0–{max}"))?,
            None => max,
        };
        Ok(Self { base, prefix })
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self.base, ip) {
            (IpAddr::V4(b), IpAddr::V4(a)) => {
                let mask = u32::MAX.checked_shl(32 - self.prefix as u32).unwrap_or(0);
                u32::from(b) & mask == u32::from(*a) & mask
            }
            (IpAddr::V6(b), IpAddr::V6(a)) => {
                let mask = u128::MAX.checked_shl(128 - self.prefix as u32).unwrap_or(0);
                u128::from(b) & mask == u128::from(*a) & mask
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn ip_ranges() {
        let r = IpRange::parse("10.0.0.0/8").unwrap();
        assert!(r.contains(&ip("10.255.1.2")));
        assert!(!r.contains(&ip("11.0.0.1")));

        let single = IpRange::parse("203.0.113.5").unwrap();
        assert!(single.contains(&ip("203.0.113.5")));
        assert!(!single.contains(&ip("203.0.113.6")));

        let all = IpRange::parse("0.0.0.0/0").unwrap();
        assert!(all.contains(&ip("8.8.8.8")));

        let v6 = IpRange::parse("2001:db8::/32").unwrap();
        assert!(v6.contains(&ip("2001:db8:1::5")));
        assert!(!v6.contains(&ip("2001:db9::1")));
        assert!(!v6.contains(&ip("10.0.0.1")), "v4 never matches a v6 range");
    }

    #[test]
    fn rejects_bad_ranges() {
        assert!(IpRange::parse("10.0.0.0/33").is_err());
        assert!(IpRange::parse("not-an-ip").is_err());
        assert!(IpRange::parse("10.0.0.0/x").is_err());
    }

    #[test]
    fn validation() {
        assert!(DetectionSettings::default().validate().is_ok());
        let bad = DetectionSettings { rate_threshold: 1, ..Default::default() };
        assert!(bad.validate().is_err());
        let bad = DetectionSettings { allowlist: vec!["10.0.0.0/99".into()], ..Default::default() };
        assert!(bad.validate().unwrap_err().contains("10.0.0.0/99"));
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("ht-settings-{}", std::process::id()));
        let s = DetectionSettings {
            rate_threshold: 20,
            allowlist: vec!["192.168.0.0/16".into()],
            ..Default::default()
        };
        s.save(&dir).unwrap();
        assert_eq!(DetectionSettings::load(&dir), s);

        // A corrupt file falls back to defaults instead of failing startup
        std::fs::write(dir.join(SETTINGS_FILE), "{ not json").unwrap();
        assert_eq!(DetectionSettings::load(&dir), DetectionSettings::default());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
