// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The values of Divi Core's multi-value sporks 13 to 16, as consensus reads
//! them (spork.cpp:90-141, :210-221, :585-760).
//!
//! Each spork keeps a list of signed entries in time order. An entry's value is
//! text of integers split by `;`; its last number is the block height from which
//! it applies. At a height, the entry in force is the last one in the list whose
//! height has been reached and which was signed before the block's time. That
//! entry is then used only if its value is valid.

use divi_primitives::constants::COIN;
use divi_primitives::Amount;

/// Spork ids (spork.h:29-39)
pub mod ids {
    pub const BLOCK_PAYMENTS: i32 = 10012;
    pub const TX_FEE: i32 = 10013;
    pub const BLOCK_VALUE: i32 = 10014;
    pub const LOTTERY_TICKET_MIN_VALUE: i32 = 10015;
}

/// One signed entry of a multi-value spork
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SporkEntry {
    /// The entry's value text
    pub value: String,
    /// When it was signed (seconds)
    pub time_signed: i64,
}

impl SporkEntry {
    pub fn new(value: impl Into<String>, time_signed: i64) -> Self {
        Self {
            value: value.into(),
            time_signed,
        }
    }
}

/// How a block's payments are split, in percent (`BlockPaymentSporkValue`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RewardDistribution {
    pub stake: i32,
    pub masternode: i32,
    pub treasury: i32,
    pub proposals: i32,
    pub charity: i32,
}

/// Fee settings (`TxFeeSporkValue`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxFeeValue {
    pub tx_value_multiplier: i32,
    pub tx_size_multiplier: i32,
    pub max_fee: i32,
    pub min_fee_per_kb: i32,
}

/// The numbers of an entry: Divi Core's `ParseDataPayload` reads integers up to
/// the first that does not parse (spork.cpp:559-575)
fn parse_numbers(text: &str) -> Vec<i32> {
    let mut numbers = Vec::new();
    for token in text.split(';') {
        match token.parse::<i32>() {
            Ok(n) => numbers.push(n),
            Err(_) => break,
        }
    }
    numbers
}

/// An entry, read as one kind of value; `None` is Divi Core's default-made
/// value (activation height 0, not valid)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Parsed<T> {
    value: Option<T>,
    activation: i64,
}

impl<T> Parsed<T> {
    fn none() -> Self {
        Self {
            value: None,
            activation: 0,
        }
    }
}

fn parse_payment(text: &str) -> Parsed<RewardDistribution> {
    let n = parse_numbers(text);
    if n.len() != 6 || n[5] <= 0 {
        // `SporkMultiValue::IsValid` wants a height above 0
        return Parsed {
            value: None,
            activation: if n.len() == 6 { n[5] as i64 } else { 0 },
        };
    }
    // The five percentages add up to 100 (spork.cpp:623-634)
    let sum = n[..5].iter().fold(0i32, |a, b| a.wrapping_add(*b));
    Parsed {
        value: (sum == 100).then_some(RewardDistribution {
            stake: n[0],
            masternode: n[1],
            treasury: n[2],
            proposals: n[3],
            charity: n[4],
        }),
        activation: n[5] as i64,
    }
}

fn parse_pair(text: &str, valid: impl Fn(i32) -> bool) -> Parsed<i32> {
    let n = parse_numbers(text);
    if n.len() != 2 {
        return Parsed::none();
    }
    Parsed {
        value: (n[1] > 0 && valid(n[0])).then_some(n[0]),
        activation: n[1] as i64,
    }
}

fn parse_fee(text: &str) -> Parsed<TxFeeValue> {
    // Divi Core wants six numbers and reads the first five (spork.cpp:735-745)
    let n = parse_numbers(text);
    if n.len() != 6 {
        return Parsed::none();
    }
    let ok = n[4] > 0 && n[0] > 0 && n[1] > 0 && n[2] > 0 && n[3] > 0;
    Parsed {
        value: ok.then_some(TxFeeValue {
            tx_value_multiplier: n[0],
            tx_size_multiplier: n[1],
            max_fee: n[2],
            min_fee_per_kb: n[3],
        }),
        activation: n[4] as i64,
    }
}

/// `GetActiveMultiValueSpork` (spork.h:210-221): the last entry whose height is
/// reached and which was signed before the block's time, valid or not; a valid
/// one comes back with its activation height
fn active_with_height<T: Copy>(
    entries: &[SporkEntry],
    parse: impl Fn(&str) -> Parsed<T>,
    height: u32,
    block_time: i64,
) -> Option<(T, i64)> {
    let mut chosen = None;
    for entry in entries {
        let parsed = parse(&entry.value);
        if height as i64 >= parsed.activation && entry.time_signed < block_time {
            chosen = Some(parsed.value.map(|v| (v, parsed.activation)));
        }
    }
    chosen.flatten()
}

/// The entries of sporks 13 to 16 this node holds
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConsensusSporks {
    block_payments: Vec<SporkEntry>,
    tx_fee: Vec<SporkEntry>,
    block_value: Vec<SporkEntry>,
    lottery_min: Vec<SporkEntry>,
}

impl ConsensusSporks {
    /// Replace the entries of one spork (a no-op for other ids). The list is
    /// kept in time order, as Divi Core's `AddActiveSpork` does.
    pub fn set(&mut self, spork_id: i32, mut entries: Vec<SporkEntry>) {
        entries.sort_by_key(|e| e.time_signed);
        match spork_id {
            ids::BLOCK_PAYMENTS => self.block_payments = entries,
            ids::TX_FEE => self.tx_fee = entries,
            ids::BLOCK_VALUE => self.block_value = entries,
            ids::LOTTERY_TICKET_MIN_VALUE => self.lottery_min = entries,
            _ => {}
        }
    }

    /// The entries of one spork
    pub fn entries(&self, spork_id: i32) -> &[SporkEntry] {
        match spork_id {
            ids::BLOCK_PAYMENTS => &self.block_payments,
            ids::TX_FEE => &self.tx_fee,
            ids::BLOCK_VALUE => &self.block_value,
            ids::LOTTERY_TICKET_MIN_VALUE => &self.lottery_min,
            _ => &[],
        }
    }

    /// The least a coinstake must pay to hold a lottery ticket at `height`, when
    /// spork 16 sets one (`GetLotteryTicketMinimum`, spork.cpp:127-141)
    pub fn lottery_ticket_minimum(&self, height: u32, block_time: i64) -> Option<Amount> {
        if self.lottery_min.is_empty() {
            return None;
        }
        let (tickets, _) = active_with_height(
            &self.lottery_min,
            |t| parse_pair(t, |ticket| ticket > 0),
            height,
            block_time,
        )?;
        Some(Amount::from_sat(tickets as i64 * COIN))
    }

    /// The whole block value at `height`, when spork 15 sets one
    /// (`GetFullBlockValue`, spork.cpp:90-107). Its height must be a multiple of
    /// the halving interval.
    pub fn full_block_value(
        &self,
        height: u32,
        halving_interval: u32,
        block_time: i64,
    ) -> Option<Amount> {
        if self.block_value.is_empty() {
            return None;
        }
        let (coins, activation) = active_with_height(
            &self.block_value,
            |t| parse_pair(t, |subsidy| subsidy >= 0),
            height,
            block_time,
        )?;
        (activation % halving_interval as i64 == 0).then(|| Amount::from_sat(coins as i64 * COIN))
    }

    /// How block payments are split at `height`, when spork 13 sets it
    /// (`GetRewardDistribution`, spork.cpp:109-125). Its height must be a
    /// multiple of the halving interval.
    pub fn reward_distribution(
        &self,
        height: u32,
        halving_interval: u32,
        block_time: i64,
    ) -> Option<RewardDistribution> {
        if self.block_payments.is_empty() {
            return None;
        }
        let (split, activation) =
            active_with_height(&self.block_payments, parse_payment, height, block_time)?;
        (activation % halving_interval as i64 == 0).then_some(split)
    }

    /// The fee settings in force at `height`, when spork 14 sets them
    /// (`ExecuteMultiValueSpork`, spork.cpp:286-302)
    pub fn tx_fee(&self, height: u32, block_time: i64) -> Option<TxFeeValue> {
        active_with_height(&self.tx_fee, parse_fee, height, block_time).map(|(v, _)| v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(id: i32, entries: &[(&str, i64)]) -> ConsensusSporks {
        let mut s = ConsensusSporks::default();
        s.set(
            id,
            entries
                .iter()
                .map(|(v, t)| SporkEntry::new(*v, *t))
                .collect(),
        );
        s
    }

    #[test]
    fn lottery_minimum_follows_the_entry_in_force() {
        let s = with(
            ids::LOTTERY_TICKET_MIN_VALUE,
            &[("5000;100", 1000), ("2000;200", 2000)],
        );
        // before the first height, or before it was signed: none
        assert_eq!(s.lottery_ticket_minimum(99, 5000), None);
        assert_eq!(s.lottery_ticket_minimum(150, 1000), None);
        // the first entry
        assert_eq!(
            s.lottery_ticket_minimum(150, 1001),
            Some(Amount::from_divi(5000))
        );
        // the later entry takes over at its height and when it was signed
        assert_eq!(
            s.lottery_ticket_minimum(200, 5000),
            Some(Amount::from_divi(2000))
        );
        assert_eq!(
            s.lottery_ticket_minimum(200, 2000),
            Some(Amount::from_divi(5000))
        );
        assert_eq!(
            ConsensusSporks::default().lottery_ticket_minimum(500, 9),
            None
        );
    }

    #[test]
    fn an_entry_in_force_that_is_not_valid_hides_the_earlier_ones() {
        // Divi Core picks the entry first and checks it after (spork.cpp:131-138)
        let s = with(
            ids::LOTTERY_TICKET_MIN_VALUE,
            &[("5000;100", 1000), ("0;200", 2000), ("junk", 3000)],
        );
        assert_eq!(
            s.lottery_ticket_minimum(150, 2500),
            Some(Amount::from_divi(5000))
        );
        assert_eq!(s.lottery_ticket_minimum(250, 2500), None);
        // text that does not read has height 0, so it is in force at once
        assert_eq!(s.lottery_ticket_minimum(150, 9999), None);
    }

    #[test]
    fn block_value_and_payments_need_a_height_on_the_halving_interval() {
        let value = with(ids::BLOCK_VALUE, &[("2000;200", 10)]);
        assert_eq!(
            value.full_block_value(200, 100, 11),
            Some(Amount::from_divi(2000))
        );
        assert_eq!(value.full_block_value(199, 100, 11), None);
        let off = with(ids::BLOCK_VALUE, &[("2000;250", 10)]);
        assert_eq!(off.full_block_value(300, 100, 11), None);
        let zero = with(ids::BLOCK_VALUE, &[("0;200", 10)]);
        assert_eq!(zero.full_block_value(200, 100, 11), Some(Amount::ZERO));

        let pay = with(ids::BLOCK_PAYMENTS, &[("50;30;10;5;5;200", 10)]);
        let split = pay.reward_distribution(200, 100, 11).unwrap();
        assert_eq!(
            (
                split.stake,
                split.masternode,
                split.treasury,
                split.proposals,
                split.charity
            ),
            (50, 30, 10, 5, 5)
        );
        // the five must add up to 100
        let bad = with(ids::BLOCK_PAYMENTS, &[("50;30;10;5;6;200", 10)]);
        assert_eq!(bad.reward_distribution(200, 100, 11), None);
        // six numbers exactly
        let short = with(ids::BLOCK_PAYMENTS, &[("50;30;10;5;5", 10)]);
        assert_eq!(short.reward_distribution(200, 100, 11), None);
    }

    #[test]
    fn fee_entry_needs_six_numbers_and_reads_five() {
        let s = with(ids::TX_FEE, &[("10000;300;100000;20000;50;0", 10)]);
        assert_eq!(
            s.tx_fee(50, 11),
            Some(TxFeeValue {
                tx_value_multiplier: 10000,
                tx_size_multiplier: 300,
                max_fee: 100000,
                min_fee_per_kb: 20000
            })
        );
        assert_eq!(s.tx_fee(49, 11), None);
        // the five-number text Divi Core writes itself is not read back
        let five = with(ids::TX_FEE, &[("10000;300;100000;20000;50", 10)]);
        assert_eq!(five.tx_fee(50, 11), None);
    }
}
