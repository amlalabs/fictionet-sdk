//! Ordered price-level aggregates for one side of an order book.
//!
//! [`Levels`] tracks quantity and order count at each price. It has no
//! order identities, instruments, or admission rules. Callers validate
//! quantities and enforce their limits before changing the levels. There
//! is no internal level limit. Adds report level creation and reductions
//! report level removal, so a book can count levels across instruments
//! and sides. Quantity and order-count arithmetic saturates.
//!
//! Iteration is in ascending price order. Reverse it for highest bids
//! first. A level is removed when its last order leaves, not when its
//! quantity reaches zero.
//!
//! ```
//! use fictionet::stdlib::protocols::book_levels::{Aggregate, Levels};
//!
//! let mut bids = Levels::default();
//! assert!(bids.add(102_500u32, 300));
//! assert!(!bids.add(102_500, 200));
//! assert_eq!(bids.get(&102_500), Some(&Aggregate { quantity: 500, orders: 2 }));
//! assert!(!bids.reduce(&102_500, 300, true));
//! assert!(bids.reduce(&102_500, 200, true));
//! assert!(bids.is_empty());
//! ```

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;

/// Total quantity and number of orders at one price.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Aggregate {
    /// Quantity at this price.
    pub quantity: u64,
    /// Orders at this price.
    pub orders: usize,
}

/// Ordered aggregates for one side of one instrument, with caller-owned limits.
#[derive(Clone, Debug)]
pub struct Levels<P> {
    levels: BTreeMap<P, Aggregate>,
}

impl<P> Default for Levels<P> {
    fn default() -> Self {
        Self {
            levels: BTreeMap::new(),
        }
    }
}

impl<P: Ord> Levels<P> {
    /// The number of price levels.
    pub fn len(&self) -> usize {
        self.levels.len()
    }

    /// Whether there are no price levels.
    pub fn is_empty(&self) -> bool {
        self.levels.is_empty()
    }

    /// The aggregate at `price`, if present.
    pub fn get(&self, price: &P) -> Option<&Aggregate> {
        self.levels.get(price)
    }

    /// Levels in ascending price order; reverse for descending order.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (&P, &Aggregate)> + ExactSizeIterator {
        self.levels.iter()
    }

    /// Adds one order's quantity, returning whether a level was created.
    ///
    /// Both quantity and order count saturate. Zero quantity still adds
    /// an order. The caller checks admission and limits first.
    pub fn add(&mut self, price: P, quantity: u64) -> bool {
        let (level, created) = match self.levels.entry(price) {
            Entry::Occupied(entry) => (entry.into_mut(), false),
            Entry::Vacant(entry) => (entry.insert(Aggregate::default()), true),
        };
        level.quantity = level.quantity.saturating_add(quantity);
        level.orders = level.orders.saturating_add(1);
        created
    }

    /// Subtracts quantity and, if `remove_order`, one order at `price`.
    /// Returns whether the last order left and the level was removed.
    ///
    /// Subtraction saturates at zero. A missing price is unchanged and
    /// returns `false`. The caller checks the order's remaining quantity
    /// and decides whether it leaves. Zero quantity alone keeps the level.
    pub fn reduce(&mut self, price: &P, quantity: u64, remove_order: bool) -> bool {
        let Some(level) = self.levels.get_mut(price) else {
            return false;
        };
        level.quantity = level.quantity.saturating_sub(quantity);
        if remove_order {
            level.orders = level.orders.saturating_sub(1);
            if level.orders == 0 {
                self.levels.remove(price);
                return true;
            }
        }
        false
    }

    /// Replaces one order's quantity at an existing price without changing
    /// its order count. Subtracts `old` with saturation, then adds `new`
    /// with saturation. A missing price is unchanged.
    pub fn replace_quantity(&mut self, price: &P, old: u64, new: u64) {
        if let Some(level) = self.levels.get_mut(price) {
            level.quantity = level.quantity.saturating_sub(old).saturating_add(new);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_reduces_and_removes_the_last_order() {
        let mut levels = Levels::default();
        assert!(levels.add(100, 30));
        assert!(!levels.add(100, 20));
        assert_eq!(levels.len(), 1);
        assert!(!levels.reduce(&100, 10, false));
        assert_eq!(
            levels.get(&100),
            Some(&Aggregate {
                quantity: 40,
                orders: 2,
            })
        );
        assert!(!levels.reduce(&100, 20, true));
        assert_eq!(
            levels.get(&100),
            Some(&Aggregate {
                quantity: 20,
                orders: 1,
            })
        );
        assert!(levels.reduce(&100, 20, true));
        assert!(levels.is_empty());
        assert_eq!(levels.get(&100), None);
        assert!(levels.add(100, 5));
        assert_eq!(levels.get(&100).unwrap().orders, 1);
    }

    #[test]
    fn prices_iterate_in_both_directions() {
        let mut levels = Levels::default();
        for price in [30, 10, 20] {
            assert!(levels.add(price, price));
        }
        assert_eq!(levels.iter().len(), 3);
        assert_eq!(
            levels
                .iter()
                .map(|(p, a)| (*p, a.quantity))
                .collect::<Vec<_>>(),
            [(10, 10), (20, 20), (30, 30)]
        );
        assert_eq!(
            levels.iter().rev().map(|(p, _)| *p).collect::<Vec<_>>(),
            [30, 20, 10]
        );
        assert!(levels.reduce(&20, 20, true));
        assert_eq!(levels.iter().len(), 2);
        assert_eq!(*levels.iter().next().unwrap().0, 10);
        assert_eq!(*levels.iter().next_back().unwrap().0, 30);
    }

    #[test]
    fn quantity_and_order_count_saturate() {
        let mut levels = Levels::default();
        assert!(levels.add(100, u64::MAX));
        assert!(!levels.add(100, 1));
        assert_eq!(levels.get(&100).unwrap().quantity, u64::MAX);
        assert!(!levels.reduce(&100, u64::MAX, true));
        assert!(!levels.reduce(&100, 1, false));
        assert_eq!(
            levels.get(&100),
            Some(&Aggregate {
                quantity: 0,
                orders: 1,
            })
        );
        // Reaching this count by adding orders would take usize::MAX calls.
        levels.levels.get_mut(&100).unwrap().orders = usize::MAX;
        assert!(!levels.add(100, 0));
        assert_eq!(levels.get(&100).unwrap().orders, usize::MAX);
        assert!(!levels.reduce(&100, 0, true));
        assert_eq!(levels.get(&100).unwrap().orders, usize::MAX - 1);
    }

    #[test]
    fn replacement_subtracts_before_adding_and_keeps_orders() {
        let mut levels = Levels::default();
        assert!(levels.add(100, u64::MAX));
        assert!(!levels.add(100, 1));
        levels.replace_quantity(&100, 10, 20);
        assert_eq!(levels.get(&100).unwrap().quantity, u64::MAX);
        levels.replace_quantity(&100, u64::MAX, 7);
        assert_eq!(levels.get(&100).unwrap().quantity, 7);
        levels.replace_quantity(&100, 10, 3);
        assert_eq!(
            levels.get(&100),
            Some(&Aggregate {
                quantity: 3,
                orders: 2,
            })
        );
        levels.replace_quantity(&100, 3, 0);
        assert_eq!(levels.get(&100).unwrap().orders, 2);
        assert_eq!(levels.get(&100).unwrap().quantity, 0);
    }

    #[test]
    fn missing_prices_and_zero_quantity() {
        let mut levels = Levels::default();
        assert!(!levels.reduce(&100, 10, false));
        assert!(!levels.reduce(&100, 10, true));
        levels.replace_quantity(&100, 10, 20);
        assert!(levels.is_empty());
        assert!(levels.add(100, 0));
        assert!(!levels.reduce(&100, 0, false));
        assert_eq!(levels.len(), 1);
        assert!(levels.reduce(&100, 0, true));
        assert!(levels.is_empty());
        assert!(levels.add(100, 10));
        assert!(levels.reduce(&100, 0, true));
        assert!(levels.is_empty());
    }
}
