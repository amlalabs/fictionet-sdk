//! Exact decimal arithmetic for numeric keywords: normalization, comparison,
//! `multipleOf` divisibility, and the multiples that generation tries.

use super::{Limits, spend};
use fictionet::stdlib::codec::Work;
use fictionet::stdlib::protocols::json::{Number, Value};
use std::cmp::Ordering;

// Normalized coefficient digits times 10^exponent. Zero has empty digits.
#[derive(Clone, Debug)]
pub(super) struct Decimal {
    pub(super) negative: bool,
    pub(super) digits: Vec<u8>,
    pub(super) exponent: i64,
}
impl Decimal {
    pub(super) fn new(number: &Number, limits: &Limits) -> Result<Self, &'static str> {
        let text = number.text();
        let (mantissa, exp) = text.split_once(['e', 'E']).unwrap_or((text, "0"));
        let exponent: i64 = exp.parse().map_err(|_| "number_exponent")?;
        if exponent.unsigned_abs() > limits.number_exponent as u64 {
            return Err("number_exponent");
        }
        let fraction = mantissa.split_once('.').map_or(0, |(_, s)| s.len());
        let mut digits: Vec<u8> = mantissa
            .bytes()
            .filter(u8::is_ascii_digit)
            .map(|b| b - b'0')
            .collect();
        let first = digits.iter().position(|&d| d != 0).unwrap_or(digits.len());
        digits.drain(..first);
        let mut exponent = exponent - fraction as i64;
        while digits.last() == Some(&0) {
            digits.pop();
            exponent += 1;
        }
        if digits.is_empty() {
            exponent = 0;
        }
        Ok(Self {
            negative: text.starts_with('-') && !digits.is_empty(),
            digits,
            exponent,
        })
    }
    pub(super) fn integer(&self) -> bool {
        self.digits.is_empty() || self.exponent >= 0
    }
    pub(super) fn cmp(&self, other: &Self) -> Ordering {
        if self.negative != other.negative {
            return if self.negative {
                Ordering::Less
            } else {
                Ordering::Greater
            };
        }
        let magnitude = if self.digits.is_empty() || other.digits.is_empty() {
            self.digits.len().cmp(&other.digits.len())
        } else {
            (self.digits.len() as i64 + self.exponent)
                .cmp(&(other.digits.len() as i64 + other.exponent))
                .then_with(|| {
                    for i in 0..self.digits.len().max(other.digits.len()) {
                        let c = self
                            .digits
                            .get(i)
                            .unwrap_or(&0)
                            .cmp(other.digits.get(i).unwrap_or(&0));
                        if c != Ordering::Equal {
                            return c;
                        }
                    }
                    Ordering::Equal
                })
        };
        if self.negative {
            magnitude.reverse()
        } else {
            magnitude
        }
    }
    pub(super) fn count(n: usize) -> Self {
        Self {
            negative: false,
            digits: if n == 0 {
                vec![]
            } else {
                n.to_string().bytes().map(|b| b - b'0').collect()
            },
            exponent: 0,
        }
    }
    pub(super) fn as_usize(&self) -> Option<usize> {
        if self.negative || !self.integer() {
            return None;
        }
        if self.digits.is_empty() {
            return Some(0);
        }
        if self.exponent > usize::BITS as i64 {
            return None;
        }
        let mut n = 0usize;
        for &d in &self.digits {
            n = n.checked_mul(10)?.checked_add(d as usize)?;
        }
        for _ in 0..self.exponent {
            n = n.checked_mul(10)?;
        }
        Some(n)
    }
    // The coefficient remainder is exact. Trailing zeros of the dividend use
    // square-and-multiply, so the cost grows with log(shift), not shift.
    pub(super) fn multiple(&self, divisor: &Self, work: &mut Work) -> Result<bool, &'static str> {
        if self.digits.is_empty() {
            return Ok(true);
        }
        let shift = self.exponent - divisor.exponent;
        if shift < 0 {
            return Ok(false);
        }
        let d = &divisor.digits;
        let r = remainder(&self.digits, d, work)?;
        if r.is_empty() || shift == 0 {
            return Ok(r.is_empty());
        }
        // power = 10^shift mod d, built from the most significant bit down.
        let ten = remainder(&[1, 0], d, work)?;
        let mut power = remainder(&[1], d, work)?;
        for bit in (0..u64::BITS - (shift as u64).leading_zeros()).rev() {
            power = remainder(&product(&power, &power, work)?, d, work)?;
            if (shift as u64 >> bit) & 1 == 1 {
                power = remainder(&product(&power, &ten, work)?, d, work)?;
            }
        }
        Ok(remainder(&product(&r, &power, work)?, d, work)?.is_empty())
    }
    pub(super) fn number(&self) -> Option<Value> {
        let mut text = if self.negative {
            "-".into()
        } else {
            String::new()
        };
        if self.digits.is_empty() {
            text.push('0');
        }
        for &digit in &self.digits {
            text.push(char::from(b'0' + digit));
        }
        if self.exponent != 0 {
            text.push_str(&format!("e{}", self.exponent));
        }
        Number::from_text(&text).map(Value::Number)
    }
}
// Big-endian decimal digits without leading zeros; zero is empty.
fn remainder(dividend: &[u8], divisor: &[u8], work: &mut Work) -> Result<Vec<u8>, &'static str> {
    let mut r = Vec::<u8>::with_capacity(divisor.len().saturating_add(1));
    for &digit in dividend {
        spend(work, divisor.len().saturating_mul(12).saturating_add(1))?;
        if !r.is_empty() || digit != 0 {
            r.push(digit);
        }
        while r.len() > divisor.len() || (r.len() == divisor.len() && r.as_slice() >= divisor) {
            let mut borrow = 0i16;
            for i in 0..r.len() {
                let at = r.len() - 1 - i;
                let d = divisor.len().checked_sub(i + 1).map_or(0, |j| divisor[j]);
                let n = i16::from(r[at]) - i16::from(d) - borrow;
                r[at] = n.rem_euclid(10) as u8;
                borrow = i16::from(n < 0);
            }
            let first = r.iter().position(|&d| d != 0).unwrap_or(r.len());
            r.drain(..first);
        }
    }
    Ok(r)
}
fn product(a: &[u8], b: &[u8], work: &mut Work) -> Result<Vec<u8>, &'static str> {
    if a.is_empty() || b.is_empty() {
        return Ok(Vec::new());
    }
    spend(work, a.len().saturating_mul(b.len()).saturating_add(1))?;
    let mut sum = vec![0u32; a.len() + b.len()];
    for (i, &x) in a.iter().enumerate().rev() {
        let mut carry = 0u32;
        for (j, &y) in b.iter().enumerate().rev() {
            let t = sum[i + j + 1] + u32::from(x) * u32::from(y) + carry;
            sum[i + j + 1] = t % 10;
            carry = t / 10;
        }
        sum[i] += carry;
    }
    let first = sum.iter().position(|&d| d != 0).unwrap_or(sum.len());
    Ok(sum[first..].iter().map(|&d| d as u8).collect())
}
pub(super) fn multiply_small(d: &Decimal, n: i64) -> Option<Value> {
    let mut digits = Vec::new();
    let multiplier = u128::from(n.unsigned_abs());
    let mut carry = 0u128;
    for &digit in d.digits.iter().rev() {
        let product = u128::from(digit)
            .checked_mul(multiplier)?
            .checked_add(carry)?;
        digits.push((product % 10) as u8);
        carry = product / 10;
    }
    while carry > 0 {
        digits.push((carry % 10) as u8);
        carry /= 10;
    }
    while digits.last() == Some(&0) {
        digits.pop();
    }
    digits.reverse();
    Decimal {
        negative: (n < 0) != d.negative && !digits.is_empty(),
        digits,
        exponent: d.exponent,
    }
    .number()
}
