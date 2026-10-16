//! Token-usage accounting plumbed through `Conversation` from day one.
//!
//! Two providers, two response shapes, one accumulator. `LlmClient`
//! impls (Phase 5d) translate from each provider's `usage` payload —
//! Anthropic's `cache_creation_input_tokens` / `cache_read_input_tokens`
//! map directly; OpenAI's `cached_tokens` populates `input_cache_read`
//! and (GPT-5.6+, which bills cache writes at 1.25× input) its
//! `cache_write_tokens` populates `input_cache_write`. Pre-5.6 OpenAI
//! models omit the field — no write fee, bucket stays 0.
//!
//! Plumbing the type now means the `Conversation` API surface is
//! stable when 5d wires LLM calls in — no retrofit, no breaking
//! changes downstream.

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TokenUsage {
    /// Tokens charged at the full input rate (no cache hit, no
    /// cache write).
    pub input_uncached: u64,
    /// Tokens written to cache on this turn (charged at 1.25× input
    /// rate on both providers today: Anthropic always; OpenAI since
    /// GPT-5.6, via `prompt_tokens_details.cache_write_tokens`).
    /// Pre-5.6 OpenAI models have no write fee and report 0 here.
    pub input_cache_write: u64,
    /// Tokens served from cache. 0.10× input rate on both providers.
    /// The LlmClient impl translates each provider's response shape
    /// so callers don't care which provider answered.
    pub input_cache_read: u64,
    pub output: u64,
}

impl TokenUsage {
    /// Accumulate `other`'s counts into `self`. Used by the agent
    /// loop (Phase 6) to track lifetime-of-Conversation usage.
    pub fn add(&mut self, other: &TokenUsage) {
        self.input_uncached = self.input_uncached.saturating_add(other.input_uncached);
        self.input_cache_write = self
            .input_cache_write
            .saturating_add(other.input_cache_write);
        self.input_cache_read = self.input_cache_read.saturating_add(other.input_cache_read);
        self.output = self.output.saturating_add(other.output);
    }

    /// Total input tokens across all three buckets — useful when a
    /// caller wants raw "tokens consumed" without caring about the
    /// caching breakdown.
    pub fn input_total(&self) -> u64 {
        self.input_uncached
            .saturating_add(self.input_cache_write)
            .saturating_add(self.input_cache_read)
    }

    /// Cost in microdollars at the supplied price points. Floors
    /// to integer microdollars to keep accumulation lossless across
    /// many turns.
    pub fn cost_microdollars(&self, prices: &Pricing) -> u64 {
        let cache_write_per_mtok =
            (prices.input_per_mtok as f64 * prices.cache_write_multiplier) as u64;
        let cache_read_per_mtok =
            (prices.input_per_mtok as f64 * prices.cache_read_multiplier) as u64;

        let uncached = self.input_uncached.saturating_mul(prices.input_per_mtok) / 1_000_000;
        let written = self.input_cache_write.saturating_mul(cache_write_per_mtok) / 1_000_000;
        let read = self.input_cache_read.saturating_mul(cache_read_per_mtok) / 1_000_000;
        let output = self.output.saturating_mul(prices.output_per_mtok) / 1_000_000;
        uncached
            .saturating_add(written)
            .saturating_add(read)
            .saturating_add(output)
    }
}

/// Per-model price points. Microdollars per million tokens to avoid
/// floating-point drift on large totals; multipliers stay floats
/// because they're constants we read off the provider's page.
#[derive(Debug, Clone, Copy)]
pub struct Pricing {
    pub input_per_mtok: u64,
    /// 1.25 on Anthropic (always) and OpenAI GPT-5.6+ (write fee
    /// introduced at 5.6; pre-5.6 models never populate the write
    /// bucket, so the multiplier is moot for them).
    pub cache_write_multiplier: f64,
    /// 0.10 (90% discount) on both providers.
    pub cache_read_multiplier: f64,
    pub output_per_mtok: u64,
}

impl Pricing {
    /// Anthropic Opus 4.7 / 4.8 reference pricing: $5/MTok in, $25/MTok
    /// out (corrected 2026-06-07 from a stale $15/$75 — the old Opus 4/4.1
    /// list price). Internal spend-checkpoint use only (never displayed).
    pub const ANTHROPIC_OPUS_4: Pricing = Pricing {
        input_per_mtok: 5_000_000, // $5 → 5 million microdollars
        cache_write_multiplier: 1.25,
        cache_read_multiplier: 0.10,
        output_per_mtok: 25_000_000, // $25/MTok
    };

    /// OpenAI flagship (gpt-5.6-sol) reference pricing: $5/MTok in,
    /// $30/MTok out.
    ///
    /// This is DELIBERATELY the pre-promo list price, not the $4/$20 the
    /// providers publish (corrected
    /// 2026-08-24). Sol's cut is promotional "at least through
    /// 2026-11-21", and this constant's only job is to decide when the
    /// internal checkpoint fires — it must never UNDER-count. Holding
    /// list here means a promo expiry costs a cloud-side edit rather than
    /// a desktop release cycle, and the worst case is a
    /// checkpoint that pauses slightly early. Do NOT "sync" it downward
    /// to match the cloud; the asymmetry is the point.
    ///
    /// Write multiplier 1.25 since 2026-07-10: OpenAI bills cache writes
    /// for 5.6+; pre-5.6 responses report a 0 write bucket, so the bump
    /// is a no-op for them. Internal spend-checkpoint use only (never
    /// displayed).
    pub const OPENAI_REFERENCE: Pricing = Pricing {
        input_per_mtok: 5_000_000,
        cache_write_multiplier: 1.25,
        cache_read_multiplier: 0.1,
        output_per_mtok: 30_000_000,
    };

    /// OpenAI gpt-5.6-terra: $2/MTok in, $12/MTok out. Corrected
    /// 2026-08-24 from a stale $2.50/$15 (the 2026-07-09 GA rate — the
    /// ~20% July cut was missed on both sides). Internal
    /// spend-checkpoint use only.
    pub const OPENAI_TERRA: Pricing = Pricing {
        input_per_mtok: 2_000_000,
        cache_write_multiplier: 1.25,
        cache_read_multiplier: 0.1,
        output_per_mtok: 12_000_000,
    };

    /// OpenAI gpt-5.6-luna: $0.20/MTok in, $1.20/MTok out. Corrected
    /// 2026-08-24 from a stale $1/$6 — the 2026-07-09 GA rate, missing
    /// the ~80% July cut, so this over-counted by 5× and tripped the
    /// checkpoint five times too early on luna chats. Internal
    /// spend-checkpoint use only.
    pub const OPENAI_LUNA: Pricing = Pricing {
        input_per_mtok: 200_000,
        cache_write_multiplier: 1.25,
        cache_read_multiplier: 0.1,
        output_per_mtok: 1_200_000,
    };

    /// Anthropic Sonnet reference pricing: $2/MTok in, $10/MTok out.
    /// Corrected 2026-08-24 from $3/$15 — Anthropic made Sonnet 5's
    /// launch "introductory" $2/$10 permanent and cancelled the
    /// scheduled Sept-1 increase. Also a safe upper bound for Haiku
    /// ($1/$5) and for the retired Sonnet 4.6 (aliased cloud-side to
    /// Sonnet 5, so it bills at this rate anyway). Used by
    /// [`pricing_for_model`] for the agent loop's internal spend
    /// checkpoint (never displayed to the user).
    pub const ANTHROPIC_SONNET: Pricing = Pricing {
        input_per_mtok: 2_000_000,
        cache_write_multiplier: 1.25,
        cache_read_multiplier: 0.10,
        output_per_mtok: 10_000_000,
    };

    /// Haiku 4.5's real rate ($1/MTok in, $5/MTok out). Not used for
    /// pricing — [`pricing_for_model`] deliberately routes Haiku to
    /// [`Pricing::ANTHROPIC_SONNET`] rather than carry a fourth Anthropic
    /// rate for a figure that is never displayed. It exists so that
    /// choice can be machine-checked: see the `const _` below.
    const HAIKU_ACTUAL: Pricing = Pricing {
        input_per_mtok: 1_000_000,
        cache_write_multiplier: 1.25,
        cache_read_multiplier: 0.10,
        output_per_mtok: 5_000_000,
    };

    /// Zero rate for local (BYOM) models — inference runs on the
    /// user's own hardware, so the marginal provider cost is zero by
    /// definition. With this, `checkpoint_rounds` (not cost) is the
    /// effective bound for local chats. Internal use only.
    pub const LOCAL_ZERO: Pricing = Pricing {
        input_per_mtok: 0,
        cache_write_multiplier: 0.0,
        cache_read_multiplier: 0.0,
        output_per_mtok: 0,
    };
}

/// Machine-check the Haiku shortcut in [`pricing_for_model`]: routing Haiku
/// to the Sonnet constant is only sound while Sonnet is the DEARER of the
/// two, since this figure must never under-count. It holds comfortably today
/// ($2/$10 against $1/$5), but Sonnet has now been cut twice — if a future
/// cut ever crosses below Haiku, this fails the BUILD rather than silently
/// turning a safe upper bound into an under-count, and the Haiku arm needs
/// its own constant.
const _: () = {
    assert!(Pricing::ANTHROPIC_SONNET.input_per_mtok >= Pricing::HAIKU_ACTUAL.input_per_mtok);
    assert!(Pricing::ANTHROPIC_SONNET.output_per_mtok >= Pricing::HAIKU_ACTUAL.output_per_mtok);
};

/// Resolve a model id to a [`Pricing`] for the agent loop's
/// **internal** spend checkpoint. This figure is NEVER shown in the
/// UI — it only decides *when* the loop pauses for a one-click
/// checkpoint. It must therefore never UNDER-count **cloud** spend:
/// an unknown model falls back to Opus (the priciest reference) so an
/// unrecognized model trips the guard slightly early rather than
/// overrunning the intended spend ceiling. Local (BYOM) ids are the
/// one deliberate exception — see the first arm.
pub fn pricing_for_model(model: &str) -> Pricing {
    // Local (BYOM) models bill at zero: inference runs on hardware the
    // user owns. This exemption is keyed on the SAME predicate the
    // factory routes with (`llm::is_local_model`) so pricing and
    // routing cannot diverge — a divergence would zero-price a CLOUD
    // model and silently kill the $5 checkpoint (pinned by
    // `pricing_predicate_matches_local_routing`).
    if crate::llm::is_local_model(model) {
        return Pricing::LOCAL_ZERO;
    }
    let m = model.to_ascii_lowercase();
    if m.contains("opus") {
        Pricing::ANTHROPIC_OPUS_4
    } else if m.contains("sonnet") {
        Pricing::ANTHROPIC_SONNET
    } else if m.contains("haiku") {
        // Haiku is cheaper than Sonnet; billing at Sonnet is a safe
        // upper bound (over-counting only pauses early) and avoids a
        // separate constant for a figure that is never displayed.
        Pricing::ANTHROPIC_SONNET
    } else if m.contains("luna") {
        // gpt-5.6-luna ($1/$6) — must match BEFORE the generic gpt arm.
        Pricing::OPENAI_LUNA
    } else if m.contains("terra") {
        // gpt-5.6-terra ($2.50/$15) — before the generic gpt arm.
        Pricing::OPENAI_TERRA
    } else if m.contains("gpt") || m.contains("openai") {
        // Product OpenAI flagship is `gpt-5.6-sol`; OPENAI_REFERENCE
        // mirrors its cloud-metered rate (== the retired gpt-5.5's
        // in/out, so stale 5.5 / 5.4-mini ids ride it as a safe upper
        // bound). The rounds checkpoint + per-command modal are the
        // hard bounds regardless of this figure's precision.
        Pricing::OPENAI_REFERENCE
    } else {
        // Unknown / future model — Opus is the priciest Anthropic
        // reference, so an unrecognized (Anthropic-shaped) model id
        // trips the spend checkpoint early rather than overrunning.
        Pricing::ANTHROPIC_OPUS_4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_accumulates_each_bucket() {
        let mut total = TokenUsage::default();
        total.add(&TokenUsage {
            input_uncached: 100,
            input_cache_write: 200,
            input_cache_read: 300,
            output: 400,
        });
        total.add(&TokenUsage {
            input_uncached: 1,
            input_cache_write: 2,
            input_cache_read: 3,
            output: 4,
        });
        assert_eq!(total.input_uncached, 101);
        assert_eq!(total.input_cache_write, 202);
        assert_eq!(total.input_cache_read, 303);
        assert_eq!(total.output, 404);
    }

    #[test]
    fn input_total_sums_three_buckets() {
        let u = TokenUsage {
            input_uncached: 100,
            input_cache_write: 50,
            input_cache_read: 1000,
            output: 0,
        };
        assert_eq!(u.input_total(), 1150);
    }

    #[test]
    fn cost_microdollars_anthropic_3000_token_first_turn() {
        // 1st turn: 3000 cache-write tokens + 200 output tokens at
        // Anthropic Opus pricing ($5/$25). 3000 * $5 * 1.25 = 18_750 µ$
        // input + 200 * $25 = 5_000 µ$ output ≈ 23_750 µ$.
        let u = TokenUsage {
            input_uncached: 0,
            input_cache_write: 3000,
            input_cache_read: 0,
            output: 200,
        };
        let cost = u.cost_microdollars(&Pricing::ANTHROPIC_OPUS_4);
        // Tolerate ±10% for rounding (we use integer division).
        assert!(
            (20_000..=30_000).contains(&cost),
            "expected ~23750, got {cost}"
        );
    }

    #[test]
    fn cost_microdollars_anthropic_subsequent_turn() {
        // Subsequent turn: 3000 cache-read tokens at 10% rate.
        // 3000 * $5/MTok * 0.10 = $0.0015 = 1500 microdollars.
        let u = TokenUsage {
            input_uncached: 0,
            input_cache_write: 0,
            input_cache_read: 3000,
            output: 0,
        };
        let cost = u.cost_microdollars(&Pricing::ANTHROPIC_OPUS_4);
        assert_eq!(cost, 1500);
    }

    #[test]
    fn saturating_arithmetic_does_not_panic_on_overflow() {
        let mut a = TokenUsage {
            input_uncached: u64::MAX - 1,
            ..TokenUsage::default()
        };
        a.add(&TokenUsage {
            input_uncached: 1000,
            ..TokenUsage::default()
        });
        // Saturated, not panicked
        assert_eq!(a.input_uncached, u64::MAX);
    }

    #[test]
    fn pricing_for_model_resolves_known_families() {
        assert_eq!(
            pricing_for_model("claude-opus-4-8").input_per_mtok,
            Pricing::ANTHROPIC_OPUS_4.input_per_mtok
        );
        assert_eq!(
            pricing_for_model("claude-sonnet-4-6").input_per_mtok,
            Pricing::ANTHROPIC_SONNET.input_per_mtok
        );
        // Haiku bills at Sonnet (a safe upper bound).
        assert_eq!(
            pricing_for_model("claude-haiku-4-5-20251001").input_per_mtok,
            Pricing::ANTHROPIC_SONNET.input_per_mtok
        );
        // Product OpenAI models: the GPT-5.6 family (2026-07-10).
        assert_eq!(
            pricing_for_model("gpt-5.6-sol").input_per_mtok,
            Pricing::OPENAI_REFERENCE.input_per_mtok
        );
        assert_eq!(
            pricing_for_model("gpt-5.6-terra").input_per_mtok,
            Pricing::OPENAI_TERRA.input_per_mtok
        );
        assert_eq!(
            pricing_for_model("gpt-5.6-luna").input_per_mtok,
            Pricing::OPENAI_LUNA.input_per_mtok
        );
        // Retired ids (aliased cloud-side; a stale selection may still
        // send them) ride the flagship reference — a safe upper bound.
        assert_eq!(
            pricing_for_model("gpt-5.5").input_per_mtok,
            Pricing::OPENAI_REFERENCE.input_per_mtok
        );
        assert_eq!(
            pricing_for_model("gpt-5.4-mini").input_per_mtok,
            Pricing::OPENAI_REFERENCE.input_per_mtok
        );
    }

    #[test]
    fn openai_reference_holds_sol_list_not_the_promo_rate() {
        // Sol's LIST rate ($5/$30), deliberately ABOVE the $4/$20 promo the
        // cloud meters through 2026-11-21. This constant only decides when
        // the internal checkpoint fires, and its contract is to never
        // under-count — so it holds list and a promo expiry costs no desktop
        // release. If a future edit "syncs" this down to the cloud figure,
        // this test is the thing that should stop it.
        let p = Pricing::OPENAI_REFERENCE;
        assert_eq!(p.input_per_mtok, 5_000_000);
        assert_eq!(p.output_per_mtok, 30_000_000);
        assert!((p.cache_read_multiplier - 0.1).abs() < f64::EPSILON);
        assert!((p.cache_write_multiplier - 1.25).abs() < f64::EPSILON);
    }

    #[test]
    fn openai_terra_and_luna_mirror_cloud_rates() {
        // published list prices: terra $2/$12, luna $0.20/$1.20 — both
        // corrected 2026-08-24 after the July cuts were missed on both
        // sides (terra −20%, luna −80%). Unlike Sol these are standard
        // rates with no expiry, so the desktop mirrors them exactly.
        assert_eq!(Pricing::OPENAI_TERRA.input_per_mtok, 2_000_000);
        assert_eq!(Pricing::OPENAI_TERRA.output_per_mtok, 12_000_000);
        assert_eq!(Pricing::OPENAI_LUNA.input_per_mtok, 200_000);
        assert_eq!(Pricing::OPENAI_LUNA.output_per_mtok, 1_200_000);
        for p in [Pricing::OPENAI_TERRA, Pricing::OPENAI_LUNA] {
            assert!((p.cache_write_multiplier - 1.25).abs() < f64::EPSILON);
            assert!((p.cache_read_multiplier - 0.1).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn anthropic_rows_keep_v0_2_2_corrected_opus_rate() {
        // Opus $5/$25 landed in v0.2.2 (corrected from the stale
        // $15/$75); the GPT fix must not disturb the Anthropic rows.
        assert_eq!(Pricing::ANTHROPIC_OPUS_4.input_per_mtok, 5_000_000);
        assert_eq!(Pricing::ANTHROPIC_OPUS_4.output_per_mtok, 25_000_000);
        // Sonnet $2/$10 (corrected 2026-08-24 from $3/$15 — Anthropic made
        // Sonnet 5's introductory rate permanent).
        assert_eq!(Pricing::ANTHROPIC_SONNET.input_per_mtok, 2_000_000);
        assert_eq!(Pricing::ANTHROPIC_SONNET.output_per_mtok, 10_000_000);
    }

    #[test]
    fn pricing_for_model_local_namespace_is_zero() {
        let p = pricing_for_model("ollama:qwen3:8b");
        assert_eq!(p.input_per_mtok, 0);
        assert_eq!(p.output_per_mtok, 0);
        // Even absurd token volume costs 0 µ$ — the rounds checkpoint
        // is the effective bound for local chats.
        let huge = TokenUsage {
            input_uncached: 50_000_000,
            input_cache_write: 1_000_000,
            input_cache_read: 1_000_000,
            output: 10_000_000,
        };
        assert_eq!(huge.cost_microdollars(&p), 0);
    }

    #[test]
    fn pricing_predicate_matches_local_routing() {
        // Adversarial ids: pricing is zero IFF the factory would route
        // the id to the local client (`llm::is_local_model`). A
        // divergence either zero-prices a cloud model (dead $5
        // checkpoint, up to 50 rounds of uncapped-by-cost spend) or
        // over-prices a local one (spurious checkpoints on free
        // tokens).
        for id in [
            "ollama:qwen3:8b",
            "ollama:claude-fake",
            "ollama:gpt-oss:20b",
        ] {
            assert!(crate::llm::is_local_model(id), "{id}");
            assert_eq!(pricing_for_model(id).input_per_mtok, 0, "{id}");
        }
        for id in [
            "ollama",
            "my-ollama-model",
            "gpt-ollama-distill",
            "claude-opus-4-8",
            "some-future-model-x",
        ] {
            assert!(!crate::llm::is_local_model(id), "{id}");
            assert!(
                pricing_for_model(id).input_per_mtok > 0,
                "{id} must never price at zero"
            );
        }
    }

    #[test]
    fn pricing_for_model_unknown_never_under_counts() {
        // An unknown/future model must bill at >= every known Anthropic
        // rate so the internal spend checkpoint can't be overrun.
        let p = pricing_for_model("some-future-model-x");
        assert_eq!(p.input_per_mtok, Pricing::ANTHROPIC_OPUS_4.input_per_mtok);
        assert!(p.input_per_mtok >= Pricing::ANTHROPIC_SONNET.input_per_mtok);
        assert!(p.output_per_mtok >= Pricing::ANTHROPIC_SONNET.output_per_mtok);
    }
}
