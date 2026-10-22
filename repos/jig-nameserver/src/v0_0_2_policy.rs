//! Which suffixes this nameserver serves, and who may register what on each:
//! open or closed registration, a minimum alias length, reserved names with
//! near-miss matching, and a per-suffix allowlist of DIDs and their names.

use std::collections::HashMap;

use anyhow::{Context, Result, bail};
use std::sync::Arc;

use jig_config::v0_0_2_server::{
    NameserverSection, PoolPolicy, PowPolicy, Registration, SuffixConfig,
};

use crate::v0_0_2_pow_policy::Market;

/// Digests a second the slowest client a suffix means to serve is assumed to
/// manage: the one server core `jig-core`'s `benches/pow.rs` measured. Boot
/// refuses a `max_effort` that would not fit `max_solve_secs` at this rate.
const REFERENCE_DIGESTS_PER_SEC: u64 = 5_500_000;

/// Every suffix this nameserver serves, in config order.
#[derive(Debug, Clone)]
pub struct Suffixes {
    list: Vec<SuffixPolicy>,
}

/// One served suffix and its registration policy, checked at boot.
#[derive(Debug, Clone)]
pub struct SuffixPolicy {
    pub suffix: String,
    pub registration: Registration,
    pub min_alias_len: usize,
    reserved: Vec<String>,
    reserved_contains: Vec<String>,
    reserved_affixes: Vec<String>,
    /// Lowercased alias → the one DID that may register it past the policy.
    allow: HashMap<String, String>,
    pow: PowPolicy,
    /// The stranger pool, the effort controller and penalties.
    market: Arc<Market>,
}

/// Why a registration was refused by policy, before any proof is checked
/// against the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Closed,
    TooShort { min: usize },
    Reserved { word: String },
}

/// How a registration got past the policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Ordinary,
    /// Named in the suffix's `registration_allow`; logged.
    Allowlisted,
}

impl Suffixes {
    /// Validate the `[nameserver]` section and compile each suffix's policy.
    /// Fails on a malformed allowlist entry, so a typo surfaces at boot rather
    /// than as a refused registration on a closed suffix.
    pub fn from_config(section: &NameserverSection) -> Result<Self> {
        section.validate().map_err(anyhow::Error::msg)?;
        let list = section
            .alias_suffixes
            .iter()
            .map(SuffixPolicy::from_config)
            .collect::<Result<_>>()?;
        Ok(Self { list })
    }

    pub fn get(&self, suffix: &str) -> Option<&SuffixPolicy> {
        self.list.iter().find(|p| p.suffix == suffix)
    }

    /// The suffix a request that names none means, when there is only one.
    pub fn only(&self) -> Option<&SuffixPolicy> {
        match self.list.as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &SuffixPolicy> {
        self.list.iter()
    }
}

impl SuffixPolicy {
    fn from_config(cfg: &SuffixConfig) -> Result<Self> {
        jig_core::naming::Name::parse(&format!("x@{}", cfg.suffix)).with_context(|| {
            format!(
                "suffix `{}` is not a dotted name of [a-z0-9-] labels",
                cfg.suffix
            )
        })?;
        let mut allow = HashMap::new();
        for entry in &cfg.registration_allow {
            jig_core::Did::from_did_jig_string(&entry.did).with_context(|| {
                format!(
                    "suffix `{}`: registration_allow DID `{}` is not did:jig:z<base32>",
                    cfg.suffix, entry.did
                )
            })?;
            if entry.aliases.is_empty() {
                bail!(
                    "suffix `{}`: registration_allow entry for `{}` names no aliases",
                    cfg.suffix,
                    entry.did
                );
            }
            for alias in &entry.aliases {
                let name = jig_core::naming::Name::parse(&format!("{alias}@{}", cfg.suffix))
                    .with_context(|| {
                        format!(
                            "suffix `{}`: registration_allow alias `{alias}` is not a valid alias",
                            cfg.suffix
                        )
                    })?;
                if let Some(other) = allow.insert(name.alias.clone(), entry.did.clone())
                    && other != entry.did
                {
                    bail!(
                        "suffix `{}`: registration_allow grants `{}` to both `{other}` and `{}`",
                        cfg.suffix,
                        name.alias,
                        entry.did
                    );
                }
            }
        }
        Ok(Self {
            suffix: cfg.suffix.clone(),
            registration: cfg.registration,
            min_alias_len: cfg.min_alias_len,
            reserved: cfg.reserved.iter().map(|w| fold(w)).collect(),
            reserved_contains: cfg.reserved_contains.iter().map(|w| fold(w)).collect(),
            reserved_affixes: cfg.reserved_affixes.iter().map(|w| fold(w)).collect(),
            allow,
            pow: checked_pow(&cfg.suffix, &cfg.pow)?,
            market: Arc::new(Market::new(
                cfg.pow.clone(),
                checked_pool(&cfg.suffix, &cfg.pool, &cfg.pow)?,
            )),
        })
    }

    /// This suffix's pool, controller and penalties.
    pub fn market(&self) -> &Market {
        &self.market
    }

    /// Whether register, renew and rotate on this suffix carry proof-of-work.
    pub fn requires_pow(&self) -> bool {
        self.pow.min_effort > 0
    }

    /// The effort a registration of the lowercased local part `alias` by
    /// `did` from `ip` is asked for. An allowlisted one pays `min_effort`
    /// (R1 decision 3); an ordinary one what the [`Market`] prices: the
    /// controller's suggestion, the length multiplier and penalties.
    pub fn register_effort(&self, admission: Admission, alias: &str, did: &str, ip: &str) -> u64 {
        if admission == Admission::Allowlisted {
            return self.pow.min_effort;
        }
        self.market.register_effort(alias, did, ip)
    }

    /// What renew and rotate by the holder pay (JEP-0008 rule 31). `0` when
    /// the suffix asks no work.
    pub fn renew_effort(&self) -> u64 {
        if self.requires_pow() {
            self.pow.renew_effort
        } else {
            0
        }
    }

    /// The puzzle algorithm this suffix asks for.
    pub fn pow_alg(&self) -> u8 {
        self.pow.alg
    }

    /// May `did` register the lowercased local part `alias` here?
    pub fn admit(&self, did: &str, alias: &str) -> Result<Admission, Refusal> {
        if self.allow.get(alias).is_some_and(|d| d == did) {
            return Ok(Admission::Allowlisted);
        }
        if !matches!(self.registration, Registration::Open) {
            return Err(Refusal::Closed);
        }
        if alias.chars().count() < self.min_alias_len {
            return Err(Refusal::TooShort {
                min: self.min_alias_len,
            });
        }
        if let Some(word) = self.reserved_hit(alias) {
            return Err(Refusal::Reserved { word });
        }
        Ok(Admission::Ordinary)
    }

    /// The reserved word `alias` collides with, after normalization:
    /// - equal to a `reserved` word;
    /// - containing a `reserved_contains` word anywhere;
    /// - starting or ending with a `reserved_affixes` word.
    fn reserved_hit(&self, alias: &str) -> Option<String> {
        let a: Vec<char> = fold(alias).chars().collect();
        let word = |w: &String| w.chars().collect::<Vec<char>>();
        let found = self
            .reserved
            .iter()
            .find(|w| a.len() == w.chars().count() && matches_at(&a, 0, &word(w)))
            .or_else(|| {
                self.reserved_contains.iter().find(|w| {
                    let w = word(w);
                    (0..a.len()).any(|i| matches_at(&a, i, &w))
                })
            })
            .or_else(|| {
                self.reserved_affixes.iter().find(|w| {
                    let w = word(w);
                    matches_at(&a, 0, &w)
                        || a.len()
                            .checked_sub(w.len())
                            .is_some_and(|start| matches_at(&a, start, &w))
                })
            });
        found.cloned()
    }
}

/// Check a suffix's `pow` table: a registered algorithm, efforts in order and
/// under JEP-0008's ceiling, and a `max_effort` that fits `max_solve_secs`.
fn checked_pow(suffix: &str, pow: &PowPolicy) -> Result<PowPolicy> {
    if jig_core::pow::Alg::from_id(pow.alg).is_none() {
        bail!(
            "suffix `{suffix}`: pow.alg {} is not a registered algorithm",
            pow.alg
        );
    }
    if pow.min_effort == 0 {
        return Ok(pow.clone());
    }
    if pow.min_effort > pow.max_effort || pow.renew_effort > pow.max_effort {
        bail!(
            "suffix `{suffix}`: pow.min_effort {} and pow.renew_effort {} must be at most \
             pow.max_effort {}",
            pow.min_effort,
            pow.renew_effort,
            pow.max_effort
        );
    }
    if pow.max_effort > jig_core::pow::MAX_EFFORT {
        bail!(
            "suffix `{suffix}`: pow.max_effort {} is above JEP-0008's ceiling of {} (rule 19)",
            pow.max_effort,
            jig_core::pow::MAX_EFFORT
        );
    }
    let ttl = crate::v0_0_2::DEFAULT_CHALLENGE_TTL.as_secs();
    if pow.max_solve_secs.saturating_mul(2) > ttl {
        bail!(
            "suffix `{suffix}`: pow.max_solve_secs {} must be at most half the challenge \
             lifetime of {ttl} s, or slow solves outlive their challenge",
            pow.max_solve_secs
        );
    }
    if pow.max_effort > pow.max_solve_secs.saturating_mul(REFERENCE_DIGESTS_PER_SEC) {
        bail!(
            "suffix `{suffix}`: pow.max_effort {} cannot be solved in pow.max_solve_secs {} at \
             {REFERENCE_DIGESTS_PER_SEC} digests a second",
            pow.max_effort,
            pow.max_solve_secs
        );
    }
    if pow.short_name_factor == 0 {
        bail!("suffix `{suffix}`: pow.short_name_factor must be at least 1");
    }
    Ok(pow.clone())
}

/// Check a suffix's `pool` table when it is on.
///
/// A queued registration still has to consume its challenge, so the longest
/// solve plus the longest wait must fit the challenge's lifetime. Bounding
/// the wait here also keeps `Market::admit`'s deadline arithmetic in range.
fn checked_pool(suffix: &str, pool: &PoolPolicy, pow: &PowPolicy) -> Result<PoolPolicy> {
    if pool.enabled {
        let ttl = crate::v0_0_2::DEFAULT_CHALLENGE_TTL.as_secs();
        let solve = if pow.min_effort == 0 {
            0
        } else {
            pow.max_solve_secs
        };
        if solve.saturating_add(pool.queue_wait_secs) > ttl {
            bail!(
                "suffix `{suffix}`: pow.max_solve_secs {solve} plus pool.queue_wait_secs {} \
                 must be at most the challenge lifetime of {ttl} s, or a queued registration \
                 outlives its challenge",
                pool.queue_wait_secs
            );
        }
    }
    if pool.enabled
        && (pool.strangers_per_hour == 0
            || pool.burst == 0
            || pool.queue_len == 0
            || pool.controller_window_secs == 0)
    {
        bail!(
            "suffix `{suffix}`: pool.strangers_per_hour, burst, queue_len and \
             controller_window_secs must each be at least 1"
        );
    }
    Ok(pool.clone())
}

/// Drop separators and fold digit lookalikes: `0→o`, `3→e`, `4→a`, `5→s`,
/// `7→t`. `1` is kept, and matches both `i` and `l` (see [`matches_at`]).
fn fold(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '-' | '_' | '.'))
        .map(|c| match c {
            '0' => 'o',
            '3' => 'e',
            '4' => 'a',
            '5' => 's',
            '7' => 't',
            c => c,
        })
        .collect()
}

/// Does `word` occur in `alias` at `start`? A `1` in the alias matches `i`,
/// `l` or `1`.
fn matches_at(alias: &[char], start: usize, word: &[char]) -> bool {
    alias.len() >= start + word.len()
        && alias[start..start + word.len()]
            .iter()
            .zip(word)
            .all(|(&a, &w)| a == w || (a == '1' && matches!(w, 'i' | 'l')))
}

#[cfg(test)]
mod tests {
    use super::*;
    use jig_config::v0_0_2_server::AllowEntry;

    fn did(byte: u8) -> String {
        jig_core::Did::from_ed25519_pubkey(&[byte; 32]).to_did_jig_string()
    }

    fn policy(cfg: SuffixConfig) -> SuffixPolicy {
        SuffixPolicy::from_config(&cfg).unwrap()
    }

    fn default_policy() -> SuffixPolicy {
        policy(SuffixConfig::new("names.example.org"))
    }

    fn reserved(alias: &str) -> bool {
        matches!(
            default_policy().admit(&did(1), alias),
            Err(Refusal::Reserved { .. })
        )
    }

    #[test]
    fn the_default_reserved_names_are_refused_exactly() {
        for alias in [
            "admin",
            "root",
            "help",
            "abuse",
            "postmaster",
            "noreply",
            "mod",
        ] {
            assert!(reserved(alias), "{alias}");
        }
        assert!(!reserved("alice"));
        assert!(
            !reserved("model"),
            "`mod` is an exact-match word, not a prefix"
        );
    }

    #[test]
    fn separators_and_digit_lookalikes_do_not_dodge_the_list() {
        for alias in [
            "adm1n",
            "r00t",
            "h3lp",
            "4buse",
            "5ecurity",
            "sy5tem",
            "no-reply",
            "post_master",
            "secur1ty",
        ] {
            assert!(reserved(alias), "{alias}");
        }
    }

    #[test]
    fn a_one_matches_both_i_and_l() {
        assert!(reserved("he1p"), "1 as l");
        assert!(reserved("adm1n"), "1 as i");
    }

    #[test]
    fn contained_words_are_refused_anywhere() {
        for alias in [
            "jig-official",
            "alicesupport",
            "supp0rt-team",
            "rejig",
            "jigsaw",
            "j1g",
        ] {
            assert!(reserved(alias), "{alias}");
        }
    }

    #[test]
    fn affix_words_are_refused_only_at_either_end() {
        for alias in [
            "admin-alice",
            "alice_admin",
            "staffer",
            "5taff",
            "teamstaff",
        ] {
            assert!(reserved(alias), "{alias}");
        }
        for alias in ["badminton", "flagstaffs", "upstaffing"] {
            assert!(!reserved(alias), "{alias} only contains an affix word");
        }
    }

    #[test]
    fn the_minimum_length_counts_the_alias_as_typed() {
        let p = default_policy();
        assert_eq!(p.admit(&did(1), "ab"), Err(Refusal::TooShort { min: 3 }));
        assert_eq!(p.admit(&did(1), "a-b"), Ok(Admission::Ordinary));
        let mut cfg = SuffixConfig::new("names.example.org");
        cfg.min_alias_len = 1;
        assert_eq!(policy(cfg).admit(&did(1), "x"), Ok(Admission::Ordinary));
    }

    /// A `pow` table that cannot work stops the boot.
    #[test]
    fn a_queue_wait_that_outlives_the_challenge_is_refused_at_boot() {
        let with = |min_effort: u64, queue_wait_secs: u64| {
            let mut cfg = SuffixConfig::new("names.example.org");
            cfg.pow = PowPolicy {
                min_effort,
                ..PowPolicy::recommended()
            };
            cfg.pool = PoolPolicy {
                queue_wait_secs,
                ..PoolPolicy::recommended()
            };
            SuffixPolicy::from_config(&cfg)
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        assert!(with(1 << 20, 10).is_ok(), "the recommended values boot");
        // 10 s to solve plus 51 s queued is past the 60 s challenge.
        assert!(with(1 << 20, 51).unwrap_err().contains("queue_wait_secs"));
        assert!(with(1 << 20, 50).is_ok());
        // With no work asked, the whole lifetime is the queue's.
        assert!(with(0, 60).is_ok());
        assert!(with(0, 61).unwrap_err().contains("queue_wait_secs"));
        // A wait that would overflow the admit deadline never boots.
        assert!(with(0, u64::MAX).unwrap_err().contains("queue_wait_secs"));
        // A pool that is off is not checked.
        let mut cfg = SuffixConfig::new("names.example.org");
        cfg.pool.enabled = false;
        cfg.pool.queue_wait_secs = u64::MAX;
        assert!(SuffixPolicy::from_config(&cfg).is_ok());
    }

    #[test]
    fn a_pow_table_that_cannot_work_is_refused_at_boot() {
        let with = |edit: fn(&mut PowPolicy)| {
            let mut cfg = SuffixConfig::new("names.example.org");
            cfg.pow = PowPolicy::recommended();
            edit(&mut cfg.pow);
            SuffixPolicy::from_config(&cfg)
                .map(|_| ())
                .map_err(|e| e.to_string())
        };
        assert!(with(|_| {}).is_ok(), "the recommended values boot");
        assert!(with(|p| p.alg = 2).unwrap_err().contains("pow.alg"));
        assert!(
            with(|p| p.min_effort = p.max_effort + 1)
                .unwrap_err()
                .contains("at most")
        );
        assert!(
            with(|p| p.renew_effort = p.max_effort + 1)
                .unwrap_err()
                .contains("at most")
        );
        assert!(
            with(|p| p.max_effort = jig_core::pow::MAX_EFFORT * 2)
                .unwrap_err()
                .contains("ceiling")
        );
        assert!(
            with(|p| p.max_solve_secs = 1)
                .unwrap_err()
                .contains("max_solve_secs")
        );
        assert!(
            with(|p| p.max_solve_secs = 31)
                .unwrap_err()
                .contains("half the challenge")
        );
        assert!(
            with(|p| p.short_name_factor = 0)
                .unwrap_err()
                .contains("short_name_factor")
        );
        // Off is off, whatever else the table says.
        assert!(
            with(|p| {
                p.min_effort = 0;
                p.max_effort = 0;
            })
            .is_ok()
        );
    }

    #[test]
    fn a_closed_suffix_refuses_ordinary_registrations() {
        let mut cfg = SuffixConfig::new("names.example.org");
        cfg.registration = Registration::Closed;
        assert_eq!(policy(cfg).admit(&did(1), "alice"), Err(Refusal::Closed));
    }

    #[test]
    fn the_allowlist_admits_only_its_did_and_its_names() {
        let mut cfg = SuffixConfig::new("names.example.org");
        cfg.registration = Registration::Closed;
        cfg.registration_allow = vec![AllowEntry {
            did: did(1),
            aliases: vec!["DJ".to_string(), "support".to_string()],
        }];
        let p = policy(cfg);
        // Past closed, short and reserved, for its own names only.
        assert_eq!(p.admit(&did(1), "dj"), Ok(Admission::Allowlisted));
        assert_eq!(p.admit(&did(1), "support"), Ok(Admission::Allowlisted));
        assert_eq!(p.admit(&did(1), "alice"), Err(Refusal::Closed));
        assert_eq!(p.admit(&did(2), "dj"), Err(Refusal::Closed));
    }

    #[test]
    fn a_bad_allowlist_entry_stops_the_boot() {
        let entry = |did: &str, aliases: &[&str]| AllowEntry {
            did: did.to_string(),
            aliases: aliases.iter().map(|a| a.to_string()).collect(),
        };
        let boot = |allow: Vec<AllowEntry>| {
            let mut cfg = SuffixConfig::new("names.example.org");
            cfg.registration_allow = allow;
            SuffixPolicy::from_config(&cfg)
                .map(|_| ())
                .unwrap_err()
                .to_string()
        };
        assert!(boot(vec![entry("did:key:z6Mk", &["dj"])]).contains("not did:jig"));
        assert!(boot(vec![entry(&did(1), &[])]).contains("names no aliases"));
        assert!(boot(vec![entry(&did(1), &["d j"])]).contains("not a valid alias"));
        let twice = boot(vec![entry(&did(1), &["dj"]), entry(&did(2), &["DJ"])]);
        assert!(twice.contains("grants `dj` to both"), "{twice}");
    }

    #[test]
    fn suffixes_resolve_by_name_and_only_one_means_the_default() {
        let one = NameserverSection {
            alias_suffix: None,
            alias_suffixes: vec![SuffixConfig::new("a.example")],
        };
        let s = Suffixes::from_config(&one).unwrap();
        assert_eq!(s.only().unwrap().suffix, "a.example");
        assert!(s.get("b.example").is_none());

        let two = NameserverSection {
            alias_suffix: None,
            alias_suffixes: vec![
                SuffixConfig::new("a.example"),
                SuffixConfig::new("b.example"),
            ],
        };
        let s = Suffixes::from_config(&two).unwrap();
        assert!(s.only().is_none());
        assert_eq!(s.get("b.example").unwrap().suffix, "b.example");
    }
}
