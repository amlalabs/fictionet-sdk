//! What a value holds on the heap, and the most a parsed value can hold.
//!
//! A layer charges its budget before it allocates (rule 9 of
//! [`layer`](fictionet::stdlib::layer)). For a value parsed from the wire
//! the allocation happens inside the parse, so the charge must come
//! before it, from a bound on what the value can hold, and the bound
//! belongs to the type: [`HeapBound`] states it next to the type, and
//! [`Heap`] measures what a built value holds, so the charge can shrink to
//! it. [`parse_paid`] does both: the bound before the parse, the measure
//! after it.
//!
//! The measure is the capacities of what a value owns, recursively: a
//! `String` or a `Vec<u8>` holds its capacity, a `Vec<T>` its places and
//! what each item holds, a `Box<T>` the `T` and what it holds. Scalars,
//! arrays of them and borrowed values hold nothing. A struct sums its
//! fields with [`heap_of!`](fictionet::heap_of), which names every field,
//! so a field added later and left out does not compile.

use std::collections::VecDeque;

use fictionet::stdlib::layer::{Budget, Owned};

/// What a value holds on the heap: the capacities of what it owns,
/// recursively, in bytes. It is what the allocator holds for the value
/// besides the value itself.
pub trait Heap {
    /// The bytes the value holds on the heap now.
    fn heap(&self) -> usize;
}

/// The most a value parsed from `len` wire bytes can hold on the heap.
///
/// Law: for every `bytes` the type's parse accepts,
/// `T::parse(bytes)?.heap() <= T::most_heap(bytes.len())`. The bound is
/// a property of the type together with its parse, so a type states it
/// once, beside the parse, and every charge for it follows from it.
pub trait HeapBound: Heap {
    /// The most a value parsed from `len` wire bytes can hold.
    fn most_heap(len: usize) -> usize;

    /// The most the value parsed from `bytes` can hold, as far as the
    /// bytes tell before they are parsed: for a message, its kind, read
    /// from a header, can hold far less than the most any kind holds.
    /// Law: `T::parse(bytes)?.heap() <= T::most_heap_of(bytes)
    /// <= T::most_heap(bytes.len())`. Without a header to read, it is
    /// [`most_heap`](Self::most_heap).
    fn most_heap_of(bytes: &[u8]) -> usize {
        Self::most_heap(bytes.len())
    }
}

macro_rules! holds_nothing {
    ($($ty:ty),* $(,)?) => {
        $(
            impl Heap for $ty {
                fn heap(&self) -> usize {
                    0
                }
            }

            impl HeapBound for $ty {
                fn most_heap(_: usize) -> usize {
                    0
                }
            }
        )*
    };
}

holds_nothing!(
    (),
    bool,
    char,
    u8,
    u16,
    u32,
    u64,
    u128,
    usize,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    f32,
    f64,
);

/// A borrowed value owns nothing.
impl<T: ?Sized> Heap for &T {
    fn heap(&self) -> usize {
        0
    }
}

impl<T: Heap, const N: usize> Heap for [T; N] {
    fn heap(&self) -> usize {
        self.iter().map(Heap::heap).sum()
    }
}

impl Heap for String {
    fn heap(&self) -> usize {
        self.capacity()
    }
}

/// A string copied from the wire whole, as `to_owned` and `to_vec` copy:
/// allocated for exactly its bytes, at most `len` of them. A parse that
/// builds a string by pushing does not meet this bound.
impl HeapBound for String {
    fn most_heap(len: usize) -> usize {
        len
    }
}

impl<T: Heap> Heap for Vec<T> {
    fn heap(&self) -> usize {
        places_heap::<T>(self.capacity()) + self.iter().map(Heap::heap).sum::<usize>()
    }
}

/// Bytes copied from the wire whole, as `to_vec` copies: allocated for
/// exactly their bytes, at most `len` of them. A parse that builds them
/// by pushing does not meet this bound.
impl HeapBound for Vec<u8> {
    fn most_heap(len: usize) -> usize {
        len
    }
}

impl<T: Heap> Heap for VecDeque<T> {
    fn heap(&self) -> usize {
        places_heap::<T>(self.capacity()) + self.iter().map(Heap::heap).sum::<usize>()
    }
}

impl<T: Heap> Heap for Box<T> {
    fn heap(&self) -> usize {
        size_of::<T>() + (**self).heap()
    }
}

/// A boxed value holds its own size and what it holds.
impl<T: HeapBound> HeapBound for Box<T> {
    fn most_heap(len: usize) -> usize {
        size_of::<T>().saturating_add(T::most_heap(len))
    }
}

impl Heap for Box<str> {
    fn heap(&self) -> usize {
        self.len()
    }
}

impl<T: Heap> Heap for Box<[T]> {
    fn heap(&self) -> usize {
        places_heap::<T>(self.len()) + self.iter().map(Heap::heap).sum::<usize>()
    }
}

impl<T: Heap> Heap for Option<T> {
    fn heap(&self) -> usize {
        self.as_ref().map_or(0, Heap::heap)
    }
}

/// Absent, it holds nothing; present, what its value can.
impl<T: HeapBound> HeapBound for Option<T> {
    fn most_heap(len: usize) -> usize {
        T::most_heap(len)
    }
}

impl<A: Heap, B: Heap> Heap for (A, B) {
    fn heap(&self) -> usize {
        self.0.heap() + self.1.heap()
    }
}

impl<A: Heap, B: Heap, C: Heap> Heap for (A, B, C) {
    fn heap(&self) -> usize {
        self.0.heap() + self.1.heap() + self.2.heap()
    }
}

/// The bytes `places` places of `T` take.
fn places_heap<T>(places: usize) -> usize {
    places.saturating_mul(size_of::<T>())
}

/// The most places a vector of `T` holding `items` items can have when it
/// grew by pushes, extends, `collect` or amortized `reserve`: such a
/// vector at most doubles past what it needs, from a first allocation of
/// a few places (eight for bytes, four for most items, one for items over
/// a kilobyte). It does not cover a vector made with a guessed capacity.
pub const fn most_places<T>(items: usize) -> usize {
    if items == 0 {
        return 0;
    }
    let first = if size_of::<T>() == 1 {
        8
    } else if size_of::<T>() <= 1024 {
        4
    } else {
        1
    };
    let doubled = items.saturating_mul(2);
    if doubled > first { doubled } else { first }
}

/// The most the places of a list of `T` parsed from `len` wire bytes can
/// take, when each item takes at least `per_item` of those bytes and the
/// list grew as [`most_places`] says: the rule for lists parsed from
/// separators, such as an SSH name-list, where each name takes at least
/// itself and its comma. What the items themselves hold is the caller's to
/// add.
pub const fn most_list_places<T>(len: usize, per_item: usize) -> usize {
    // Less than a byte per item would bound nothing: count at least one.
    let per_item = if per_item > 1 { per_item } else { 1 };
    let items = len / per_item;
    most_places::<T>(items).saturating_mul(size_of::<T>())
}

/// Parses `bytes` with `parse`, paid for on `budget`: the type's bound for
/// those bytes ([`HeapBound::most_heap_of`]) is charged before the parse,
/// and the charge shrinks to
/// what the value holds after it. `None`, with nothing parsed, when the
/// budget has no room for the bound: the charge was refused, and the
/// caller waits for memory as for any refusal (rule 9). A parse error
/// gives the charge back.
pub fn parse_paid<T: HeapBound, E>(
    budget: &Budget,
    bytes: &[u8],
    parse: impl FnOnce(&[u8]) -> Result<T, E>,
) -> Option<Result<Owned<T>, E>> {
    let mut charge = budget.charge(T::most_heap_of(bytes))?;
    Some(parse(bytes).map(|value| {
        let held = value.heap();
        debug_assert!(
            held <= charge.bytes(),
            "a parsed value holds {held} bytes, more than its HeapBound of {}",
            charge.bytes()
        );
        charge.shrink_to(held);
        Owned::new(value, charge)
    }))
}

/// Implements [`Heap`] for a struct as the sum of what its fields hold.
/// Every field is named, so a struct that gains a field does not compile
/// until the field is named here too; a field that holds nothing on the
/// heap, such as a number, is named like the rest.
///
/// ```
/// use fictionet::heap_of;
/// use fictionet::stdlib::codec::Heap;
///
/// struct Greeting {
///     name: String,
///     tags: Vec<String>,
///     loud: bool,
/// }
/// heap_of! { Greeting { name, tags, loud } }
///
/// let greeting = Greeting {
///     name: "ada".to_owned(),
///     tags: Vec::new(),
///     loud: false,
/// };
/// assert_eq!(greeting.heap(), greeting.name.capacity());
/// ```
#[macro_export]
macro_rules! heap_of {
    ($($ty:ty { $($field:ident),* $(,)? })*) => {
        $(
            impl $crate::stdlib::codec::Heap for $ty {
                fn heap(&self) -> usize {
                    let Self { $($field),* } = self;
                    0 $(+ $crate::stdlib::codec::Heap::heap($field))*
                }
            }
        )*
    };
}

/// Checks the [`HeapBound`] law for `T` and its parse over `inputs`: every
/// input that parses holds at most the bound for its bytes, which is at
/// most the bound for its length. At least one must parse, so a check
/// over inputs that all fail cannot pass.
#[cfg(test)]
pub(crate) fn assert_heap_bound<T: HeapBound, E>(
    inputs: impl IntoIterator<Item = impl AsRef<[u8]>>,
    parse: impl Fn(&[u8]) -> Result<T, E>,
) {
    let mut parsed = 0;
    for input in inputs {
        let bytes = input.as_ref();
        if let Ok(value) = parse(bytes) {
            parsed += 1;
            assert!(
                value.heap() <= T::most_heap_of(bytes),
                "{} bytes parse into a value holding {} bytes, more than the bound {}",
                bytes.len(),
                value.heap(),
                T::most_heap_of(bytes)
            );
            assert!(
                T::most_heap_of(bytes) <= T::most_heap(bytes.len()),
                "the bound for {} bytes, {}, is more than the bound for any of their length, {}",
                bytes.len(),
                T::most_heap_of(bytes),
                T::most_heap(bytes.len())
            );
        }
    }
    assert!(parsed > 0, "no input parsed, so the law was not checked");
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet::stdlib::codec::assert_heap_bound;
    use fictionet::{Entropy, Seed, SeededEntropy};

    /// A name and its comma-separated tags, as `name:tag,tag`: a list
    /// parsed from separators, bounded by the rule for such lists.
    #[derive(Debug)]
    struct Tagged {
        name: String,
        tags: Vec<String>,
        loud: bool,
    }

    heap_of! { Tagged { name, tags, loud } }

    impl Tagged {
        fn parse(bytes: &[u8]) -> Result<Tagged, ()> {
            let text = std::str::from_utf8(bytes).map_err(drop)?;
            let (name, tags) = text.split_once(':').ok_or(())?;
            Ok(Tagged {
                name: name.to_owned(),
                tags: if tags.is_empty() {
                    Vec::new()
                } else {
                    tags.split(',').map(str::to_owned).collect()
                },
                loud: name.ends_with('!'),
            })
        }
    }

    /// Each tag takes at least itself, which may be empty, and its comma,
    /// one byte; the strings hold at most the bytes of the input.
    impl HeapBound for Tagged {
        fn most_heap(len: usize) -> usize {
            most_list_places::<String>(len + 1, 1) + len
        }
    }

    /// Random inputs of the type's shape, with lists of the shortest items
    /// among them, which cost the most per byte.
    fn tagged_inputs(rng: &SeededEntropy) -> Vec<Vec<u8>> {
        let mut inputs = Vec::new();
        for _ in 0..512 {
            let name_len = rng.random_below(6) as usize;
            let mut input: Vec<u8> = (0..name_len)
                .map(|_| b'a' + (rng.random_below(26) as u8))
                .collect();
            input.push(b':');
            let tags = rng.random_below(40) as usize;
            let longest = rng.random_below(4) as usize;
            for tag in 0..tags {
                if tag > 0 {
                    input.push(b',');
                }
                let len = rng.random_below(longest as u64 + 1) as usize;
                input.extend((0..len).map(|_| b'x'));
            }
            inputs.push(input);
        }
        inputs
    }

    #[test]
    fn parsed_values_hold_at_most_their_bound() {
        let rng = SeededEntropy::new(Seed::from_u64(7));
        let texts: Vec<Vec<u8>> = (0..64)
            .map(|n| (0..n).map(|i| b'a' + (i % 26) as u8).collect())
            .collect();
        assert_heap_bound(&texts, |b| std::str::from_utf8(b).map(str::to_owned));
        assert_heap_bound(&texts, |b| Ok::<_, ()>(b.to_vec()));
        assert_heap_bound(&texts, |b| Ok::<_, ()>(Box::new(b.to_vec())));
        assert_heap_bound(&texts, |b| {
            Ok::<_, ()>((!b.is_empty()).then(|| String::from_utf8_lossy(b).into_owned()))
        });
        assert_heap_bound([[0u8; 4], [1, 2, 3, 4]], |b| {
            b.try_into().map(u32::from_be_bytes)
        });
        assert_heap_bound(tagged_inputs(&rng), Tagged::parse);
    }

    /// The rule for lists covers every way a vector grows by itself:
    /// pushed one by one, collected, or reserved a few at a time.
    #[test]
    fn grown_vectors_have_at_most_the_places_the_rule_allows() {
        fn check<T: Default + Clone>() {
            for items in 0..200 {
                let mut pushed = Vec::new();
                for _ in 0..items {
                    pushed.push(T::default());
                }
                let collected: Vec<T> = (0..items).map(|_| T::default()).collect();
                let mut reserved = Vec::new();
                while reserved.len() < items {
                    reserved.reserve(3.min(items - reserved.len()));
                    reserved.push(T::default());
                }
                for grown in [pushed, collected, reserved] {
                    assert!(grown.capacity() <= most_places::<T>(items));
                }
            }
        }
        check::<u8>();
        check::<u64>();
        check::<String>();
        // Items over a kilobyte.
        check::<[[u64; 32]; 5]>();
    }

    /// A field-wise measure is the sum of the fields' measures, and a
    /// vector's is its places and what each item holds.
    #[test]
    fn a_measure_sums_what_is_owned() {
        let tagged = Tagged::parse(b"name!:a,bb,ccc").unwrap();
        let tags: usize = tagged.tags.iter().map(String::capacity).sum();
        assert_eq!(
            tagged.heap(),
            tagged.name.capacity() + tagged.tags.capacity() * size_of::<String>() + tags
        );
        assert!(tagged.loud);
        let nested: Vec<Vec<u8>> = vec![vec![1; 3], Vec::with_capacity(9)];
        assert_eq!(nested.heap(), 2 * size_of::<Vec<u8>>() + 3 + 9);
        assert_eq!(Some(Box::new(7u64)).heap(), size_of::<u64>());
        assert_eq!(None::<String>.heap(), 0);
        assert_eq!(Box::<str>::from("four").heap(), 4);
    }

    /// The bound is charged before the parse and the measure after it;
    /// a bound without room parses nothing, and a failed parse holds
    /// nothing.
    #[test]
    fn parse_paid_charges_the_bound_before_and_the_measure_after() {
        let rng = SeededEntropy::new(Seed::from_u64(11));
        for input in tagged_inputs(&rng) {
            let bound = Tagged::most_heap(input.len());
            let budget = Budget::new(bound + rng.random_below(64) as usize);
            let other = budget.charge(rng.random_below(8) as usize).unwrap();
            let before = budget.used();
            let fits = bound <= budget.limit() - before;
            let mut charged_during = None;
            let paid = parse_paid(&budget, &input, |bytes| {
                charged_during = Some(budget.used());
                Tagged::parse(bytes)
            });
            match paid {
                None => {
                    assert!(!fits);
                    assert_eq!(charged_during, None, "nothing parsed without room");
                    assert_eq!(budget.used(), before);
                }
                Some(Ok(value)) => {
                    assert!(fits);
                    assert_eq!(charged_during, Some(before + bound), "the bound came first");
                    assert_eq!(value.charged(), value.heap(), "the charge is the measure");
                    assert_eq!(budget.used(), before + value.heap());
                    drop(value);
                    assert_eq!(budget.used(), before);
                }
                Some(Err(())) => unreachable!("the inputs parse"),
            }
            drop(other);
        }
        let budget = Budget::new(Tagged::most_heap(8));
        let failed = parse_paid(&budget, b"no colon", Tagged::parse);
        assert!(matches!(failed, Some(Err(()))));
        assert_eq!(budget.used(), 0, "a failed parse holds nothing");
    }

    /// A message whose first byte says its kind: `n` holds nothing, `s`
    /// holds the rest as a string.
    struct Kinded {
        text: Option<String>,
    }

    heap_of! { Kinded { text } }

    impl Kinded {
        fn parse(bytes: &[u8]) -> Result<Kinded, ()> {
            match bytes.split_first() {
                Some((b'n', _)) => Ok(Kinded { text: None }),
                Some((b's', rest)) => std::str::from_utf8(rest)
                    .map(|text| Kinded {
                        text: Some(text.to_owned()),
                    })
                    .map_err(drop),
                _ => Err(()),
            }
        }
    }

    impl HeapBound for Kinded {
        fn most_heap(len: usize) -> usize {
            len
        }
        fn most_heap_of(bytes: &[u8]) -> usize {
            match bytes.first() {
                Some(b'n') => 0,
                _ => Self::most_heap(bytes.len()),
            }
        }
    }

    /// The charge before the parse is the bound for the bytes, so a kind
    /// that holds nothing is parsed with no room at all, and the law holds
    /// for each kind.
    #[test]
    fn parse_paid_charges_the_bound_of_the_bytes() {
        let inputs = [&b"n"[..], b"nothing held", b"s", b"some text"];
        assert_heap_bound(inputs, Kinded::parse);
        let budget = Budget::new(0);
        for input in inputs {
            let paid = parse_paid(&budget, input, Kinded::parse);
            assert_eq!(paid.is_some(), input[0] == b'n');
        }
        assert_eq!(budget.used(), 0);
    }

    /// A bound without room is a refusal on the budget, so the caller's
    /// runner waits for memory as for any other.
    #[test]
    fn a_bound_without_room_is_a_refusal() {
        let budget = Budget::new(Tagged::most_heap(4)).view();
        let held = budget.charge(1).unwrap();
        let mark = budget.refusals();
        assert!(parse_paid(&budget, b"ab:c", Tagged::parse).is_none());
        assert!(budget.refused_since(mark));
        assert_eq!(budget.starved_since(mark), None);
        drop(held);
        assert!(matches!(
            parse_paid(&budget, b"ab:c", Tagged::parse),
            Some(Ok(_))
        ));
    }
}
