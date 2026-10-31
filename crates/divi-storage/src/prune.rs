//! Block-expiry pruning: retention setting and duration grammar.
//!
//! See `docs/block-expiry-pruning.md`.

use std::fmt;

/// Never prune bodies/undo for this many most-recent blocks (about 2 days at 60 s).
pub const MIN_BLOCKS_TO_KEEP: u32 = 2880;

const MONTH_SECS: u64 = 30 * 86_400;
const YEAR_SECS: u64 = 365 * 86_400;

/// Retention setting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum Expire {
    /// `-1`: keep the full chain (default).
    #[default]
    Never,
    /// `0`: keep only the minimum needed to stake and validate.
    Minimum,
    /// Keep blocks whose time is within this many seconds of now.
    Window(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpireParseError(pub String);

impl fmt::Display for ExpireParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid expire value: {}", self.0)
    }
}

impl std::error::Error for ExpireParseError {}

impl Expire {
    /// Parse `-1`, `0`, or `<integer><unit>` with unit one of `s m h d w mo y`.
    pub fn parse(input: &str) -> Result<Expire, ExpireParseError> {
        let s = input.trim();
        // The reason only, never the value: it reaches the node's exit
        // reason (R3 code 2), which names the option and why
        let err = |why: &str| ExpireParseError(why.to_string());
        if s == "-1" {
            return Ok(Expire::Never);
        }
        if s == "0" {
            return Ok(Expire::Minimum);
        }
        let digits_end = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
        let (num, unit) = s.split_at(digits_end);
        if num.is_empty() {
            return Err(err("expected -1, 0, or <number><unit> (s m h d w mo y)"));
        }
        if unit.is_empty() {
            return Err(err(
                "a bare number needs a unit (s m h d w mo y); only -1 and 0 are unitless",
            ));
        }
        let n: u64 = num.parse().map_err(|_| err("number too large"))?;
        let mult = match unit {
            "s" => 1,
            "m" => 60,
            "h" => 3_600,
            "d" => 86_400,
            "w" => 604_800,
            "mo" => MONTH_SECS,
            "y" => YEAR_SECS,
            _ => return Err(err("unknown unit (use s m h d w mo y)")),
        };
        let secs = n
            .checked_mul(mult)
            .ok_or_else(|| err("duration overflows"))?;
        if secs == 0 {
            return Ok(Expire::Minimum);
        }
        Ok(Expire::Window(secs))
    }

    pub fn is_enabled(&self) -> bool {
        !matches!(self, Expire::Never)
    }
}

impl fmt::Display for Expire {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expire::Never => write!(f, "-1"),
            Expire::Minimum => write!(f, "0"),
            Expire::Window(s) => write!(f, "{}s", s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        assert_eq!(Expire::parse("90s").unwrap(), Expire::Window(90));
        assert_eq!(Expire::parse("5m").unwrap(), Expire::Window(300));
        assert_eq!(Expire::parse("2h").unwrap(), Expire::Window(7200));
        assert_eq!(Expire::parse("30d").unwrap(), Expire::Window(30 * 86_400));
        assert_eq!(Expire::parse("2w").unwrap(), Expire::Window(14 * 86_400));
        assert_eq!(Expire::parse("1mo").unwrap(), Expire::Window(30 * 86_400));
        assert_eq!(Expire::parse("1y").unwrap(), Expire::Window(365 * 86_400));
    }

    #[test]
    fn minutes_vs_months_never_collide() {
        assert_ne!(Expire::parse("1m").unwrap(), Expire::parse("1mo").unwrap());
        assert!(Expire::parse("1M").is_err());
        assert!(Expire::parse("1mi").is_err());
    }

    #[test]
    fn special_values() {
        assert_eq!(Expire::parse("-1").unwrap(), Expire::Never);
        assert_eq!(Expire::parse("0").unwrap(), Expire::Minimum);
        assert_eq!(Expire::parse("0d").unwrap(), Expire::Minimum);
        assert_eq!(Expire::default(), Expire::Never);
        assert!(!Expire::Never.is_enabled());
        assert!(Expire::Minimum.is_enabled());
    }

    #[test]
    fn rejects_garbage() {
        for bad in [
            "",
            "30",
            "d",
            "-2",
            "-1d",
            "1.5d",
            "30 days",
            "1x",
            "abc",
            "99999999999999999999d",
        ] {
            assert!(Expire::parse(bad).is_err(), "{bad} should be rejected");
        }
    }
}
