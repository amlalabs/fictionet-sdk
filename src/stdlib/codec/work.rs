use fictionet::stdlib::codec::Error;

/// A named, finite allowance of semantic work.
/// Refused charges leave the counter unchanged.
///
/// ```
/// use fictionet::stdlib::codec::Work;
/// let mut work = Work::new("values", 10);
/// work.charge_product(2, 3, 1)?;
/// assert_eq!((work.used(), work.remaining()), (7, 3));
/// assert!(work.charge(4).is_err());
/// assert_eq!(work.used(), 7);
/// # Ok::<(), fictionet::stdlib::codec::Error>(())
/// ```
#[derive(Clone, Copy, Debug)]
pub struct Work {
    name: &'static str,
    limit: usize,
    used: usize,
}
impl Work {
    /// Starts an unused allowance.
    #[inline]
    pub fn new(name: &'static str, limit: usize) -> Self {
        Self {
            name,
            limit,
            used: 0,
        }
    }
    /// Charges units, refusing overflow or exhaustion.
    #[inline]
    pub fn charge(&mut self, units: usize) -> Result<(), Error> {
        if units > self.remaining() {
            return Err(self.refusal(units));
        }
        self.used += units;
        Ok(())
    }
    /// Charges `count * each + fixed`, refusing arithmetic overflow.
    #[inline]
    pub fn charge_product(&mut self, count: usize, each: usize, fixed: usize) -> Result<(), Error> {
        let units = count
            .checked_mul(each)
            .and_then(|n| n.checked_add(fixed))
            .ok_or_else(|| self.refusal(usize::MAX))?;
        self.charge(units)
    }
    /// Returns charged units.
    #[inline]
    pub fn used(&self) -> usize {
        self.used
    }
    /// Returns units still available.
    #[inline]
    pub fn remaining(&self) -> usize {
        self.limit - self.used
    }
    fn refusal(&self, charge: usize) -> Error {
        Error::Work {
            name: self.name,
            limit: self.limit,
            used: self.used,
            charge,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_limit_and_refusals() {
        let mut work = Work::new("test", 7);
        work.charge_product(2, 3, 1).unwrap();
        work.charge(0).unwrap();
        assert_eq!(
            work.charge(1),
            Err(Error::Work {
                name: "test",
                limit: 7,
                used: 7,
                charge: 1,
            })
        );
        assert_eq!((work.used(), work.remaining()), (7, 0));
        let mut work = Work::new("overflow", usize::MAX);
        for (count, each, fixed) in [(usize::MAX, 2, 0), (usize::MAX, 1, 1)] {
            assert_eq!(
                work.charge_product(count, each, fixed),
                Err(Error::Work {
                    name: "overflow",
                    limit: usize::MAX,
                    used: 0,
                    charge: usize::MAX,
                })
            );
            assert_eq!(work.used(), 0);
        }
        work.charge(usize::MAX).unwrap();
        assert!(work.charge(1).is_err());
        assert_eq!(work.used(), usize::MAX);
        let mut zero = Work::new("zero", 0);
        zero.charge_product(usize::MAX, 0, 0).unwrap();
        assert!(zero.charge(1).is_err());
    }
}
