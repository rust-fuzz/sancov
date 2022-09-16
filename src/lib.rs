#![doc = include_str!("../README.md")]
#![no_std]
#![deny(missing_docs)]

use core::cell::UnsafeCell;
use core::ops::Index;
use core::sync::atomic::{AtomicU8, Ordering};
use sancov_sys as sys;

/// An collection of `N` counters.
///
/// Counters must be registered by calling the
/// [`register`][crate::Counters::register] method.
///
/// The `SanitizerCoverage` consumer can observe this counter and do things like
/// e.g. provide feedback for fuzzing engines.
///
/// You can index into `Counters` with `usize` indices to get individual
/// `Counter`s.
///
/// `Counters<N>` has the same representation as `[u8; N]`. You can rely on this
/// fact and increment this counter from, for example, JIT code.
///
/// # Example
///
/// ```
/// use sancov::Counters;
///
/// // Define some counters.
/// static COUNTERS: Counters<4096> = Counters::new();
///
/// // Register the counters with the `SanitizerCoverage` consumer.
/// COUNTERS.register();
///
/// // Increment a counter.
/// COUNTERS[42].increment();
/// #
/// # #[no_mangle]
/// # pub fn __sanitizer_cov_8bit_counters_init(_: *const u8, _: *const u8) {}
/// ```
#[repr(transparent)]
pub struct Counters<const N: usize>(UnsafeCell<[u8; N]>);

unsafe impl<const N: usize> Send for Counters<N> {}
unsafe impl<const N: usize> Sync for Counters<N> {}

impl<const N: usize> Counters<N> {
    /// Construct a new set of `N` counters.
    ///
    /// # Example
    ///
    /// ```
    /// use sancov::Counters;
    ///
    /// // Define some counters.
    /// static COUNTERS: Counters<4096> = Counters::new();
    ///
    /// // Register the counters with the `SanitizerCoverage` consumer.
    /// COUNTERS.register();
    /// #
    /// # #[no_mangle]
    /// # pub fn __sanitizer_cov_8bit_counters_init(_: *const u8, _: *const u8) {}
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if `N` is zero.
    ///
    /// ```should_panic
    /// use sancov::Counters;
    ///
    /// // This will panic!
    /// let _ = Counters::<0>::new();
    /// ```
    pub const fn new() -> Self {
        let _n_cannot_be_zero = [()][(N == 0) as usize];
        Counters(UnsafeCell::new([0; N]))
    }

    /// Get the underying array of counters.
    #[inline]
    pub fn as_array(&self) -> &[Counter; N] {
        unsafe {
            let ptr: *mut [u8; N] = self.0.get();
            let ptr: *const [u8; N] = ptr as _;
            let ptr: *const [Counter; N] = ptr as _;
            &*ptr
        }
    }

    /// Register the given counters with the `SanitizerCoverage` consumer.
    ///
    /// The `SanitizerCoverage` API unfortunately does not provide any method of
    /// unregistering counters, so `&self` must be `'static`.
    ///
    /// Repeated registration is idempotent but not necessarily
    /// performant. Consider using `std::sync::Once` or [the `ctor`
    /// crate](https://crates.io/crates/ctor).
    ///
    /// # Example
    ///
    /// ```
    /// use sancov::Counters;
    ///
    /// // Define some counters.
    /// static COUNTERS: Counters<4096> = Counters::new();
    ///
    /// // Register the counters with the `SanitizerCoverage` consumer.
    /// COUNTERS.register();
    /// #
    /// # #[no_mangle]
    /// # pub fn __sanitizer_cov_8bit_counters_init(_: *const u8, _: *const u8) {}
    /// ```
    pub fn register(&'static self) {
        unsafe {
            let start = self.as_array().as_ptr() as *const u8;
            let end = start.add(N) as *const u8;
            sys::__sanitizer_cov_8bit_counters_init(start, end);
        }
    }

    /// Increment the counter at index `fxhash(x) % self.len()`.
    ///
    /// This allows you to map an unbounded number of logical counters down onto
    /// a bounded number of actual counters.
    ///
    /// Useful when:
    ///
    /// 1. You have a dynamic number of logical counters, but you have to choose
    ///    a static number of actual counters at initialization time when
    ///    registering the counters because of `SanitizerCoverage` API
    ///    constraints. Note that using this method is preferable to doing
    ///    `counters[i % counters.len()].increment()` in this situation, since
    ///    that can suffer from harmonics.
    ///
    /// 2. You have very many and very sparsely incremented logical counters. So
    ///    many logical counters that the performance of the consumer iterating
    ///    over them all would be severely impacted if you had that many actual
    ///    counters.
    ///
    /// # Example
    ///
    /// ```
    /// use sancov::Counters;
    ///
    /// static COUNTERS: Counters<16> = Counters::new();
    /// COUNTERS.register();
    ///
    /// // Increment the "i^th" counter, where `i` is larger than how many
    /// // actual counters we have.
    /// COUNTERS.hash_increment(&69);
    /// COUNTERS.hash_increment(&420);
    ///
    /// // Or increment counters named by anything that is hashable!
    /// COUNTERS.hash_increment("wheelies");
    /// COUNTERS.hash_increment("won't");
    /// COUNTERS.hash_increment("pop");
    /// COUNTERS.hash_increment("themselves!");
    /// #
    /// # #[no_mangle]
    /// # pub fn __sanitizer_cov_8bit_counters_init(_: *const u8, _: *const u8) {}
    /// ```
    #[inline]
    #[cfg(feature = "hash_increment")]
    pub fn hash_increment<T>(&self, x: &T)
    where
        T: ?Sized + core::hash::Hash,
    {
        assert_ne!(N, 0);
        let i = fxhash::hash(x) % N;
        self[i].increment();
    }
}

impl<const N: usize> Index<usize> for Counters<N> {
    type Output = Counter;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        assert!(index < N);
        &self.as_array()[index]
    }
}

/// A single 8-bit counter.
///
/// It can be incremented.
///
/// It has the same representation as a `u8`. You can rely on this fact and
/// increment this counter from, for example, JIT code.
#[repr(transparent)]
pub struct Counter(AtomicU8);

impl Counter {
    /// Increment this counter.
    ///
    /// This uses AFL++'s "NeverZero" approach, where we add the overflow carry
    /// back to the counter, so that it is never zero after its been incremented
    /// once. This avoids accidentally losing information in the face of
    /// multiples-of-256 harmonics and they found it to be faster in practice
    /// than doing a saturating add.
    ///
    /// See section 3.3 of [the AFL++
    /// paper](https://www.usenix.org/system/files/woot20-paper-fioraldi.pdf)
    /// for details.
    #[inline]
    pub fn increment(&self) {
        let count = self.0.load(Ordering::Relaxed);
        let (count, overflowed) = count.overflowing_add(1);
        self.0.store(count + (overflowed as u8), Ordering::Relaxed);
    }

    /// Increment this counter, saturating at `u8::MAX`.
    pub fn saturating_increment(&self) {
        let count = self.0.load(Ordering::Relaxed);
        self.0.store(count.saturating_add(1), Ordering::Relaxed);
    }
}

#[cfg(test)]
#[no_mangle]
pub fn __sanitizer_cov_8bit_counters_init(_: *const u8, _: *const u8) {}
