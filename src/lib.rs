//! Rust bindings to [the `SanitizerCoverage`
//! interface](https://clang.llvm.org/docs/SanitizerCoverage.html).
//!
//! These bindings are designed for generating coverage information
//! (e.g. exposing coverage in JIT code) not defining consumers of it.

#![no_std]
#![deny(missing_docs)]

use core::sync::atomic::{AtomicU8, Ordering};
use sancov_sys as sys;

/// A single 8-bit counter.
///
/// It can be incremented.
///
/// It has the same representation as a `u8`. You can rely on this fact and
/// increment this counter from, for example, JIT code.
///
/// The `SanitizerCoverage` consumer can observe this counter and do things like
/// e.g. provide feedback for fuzzing engines.
///
/// However, the consumer can't see this counter unless it is registered with
/// [`register_counters`][crate::register_counters].
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Counter(
    // This should really be `AtomicU8` but that isn't `Copy` and the whole
    // point of this type is to define `static`s with literals like
    // `[Counter::new(); 4096]`. One day, when `#![feature(inline_const)]`
    // stabilizes we will be able to make this type an actual wrapper around
    // `AtomicU8` and do things like `[const { Counter::new() }; 4096]` which
    // doesn't require `Copy`. Until then... fingers crossed this isn't UB? Or
    // at least not UB enough to get mis-optimized? ...
    u8,
);

impl Counter {
    /// Create a new counter.
    pub const fn new() -> Self {
        Counter(0)
    }

    fn as_atomic(&self) -> &AtomicU8 {
        // See comment above about how `self.0` should really be an
        // `AtomicU8`...
        unsafe {
            let ptr = &self.0 as *const u8;
            &*(ptr as *const AtomicU8)
        }
    }

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
        let count = self.as_atomic().load(Ordering::Relaxed);
        let (count, overflowed) = count.overflowing_add(1);
        self.as_atomic()
            .store(count + (overflowed as u8), Ordering::Relaxed);
    }

    /// Increment this counter, saturating at `u8::MAX`.
    pub fn saturating_increment(&self) {
        let count = self.as_atomic().load(Ordering::Relaxed);
        self.as_atomic()
            .store(count.saturating_add(1), Ordering::Relaxed);
    }
}

/// An extension trait for slices of `Counter`s.
pub trait CounterSliceExt {
    /// Increment the counter at index `fxhash(x) % self.len()`.
    ///
    /// This allows you to map an "infinited" number of logical counters down
    /// onto a bounded number of actual counters.
    ///
    /// Useful when:
    ///
    /// 1. You have a dynamic number of logical counters, but you have to choose
    ///    a static number of actual counters at initialization time when
    ///    registering the counters because of `SanitizerCoverage` API
    ///    constraints. Note that this method is preferable to doing `counters[i
    ///    % counters.len()].increment()` in this situation, since that can
    ///    suffer from harmonics.
    ///
    /// 2. You have very many and very sparsely incremented logical counters. So
    ///    many logical counters that the performance of the consumer iterating
    ///    over them all would be severely impacted if you had that many actual
    ///    counters.
    ///
    /// # Panics
    ///
    /// Panics when this slice is empty and there is no counter to increment.
    ///
    /// # Example
    ///
    /// ```
    /// use sancov::{Counter, CounterSliceExt};
    ///
    /// static COUNTERS: [Counter; 16] = [Counter::new(); 16];
    /// sancov::register_counters(&COUNTERS);
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
    #[cfg(feature = "hash_increment")]
    fn hash_increment<T>(&self, x: &T)
    where
        T: ?Sized + core::hash::Hash;
}

impl CounterSliceExt for [Counter] {
    #[inline]
    #[cfg(feature = "hash_increment")]
    fn hash_increment<T>(&self, x: &T)
    where
        T: ?Sized + core::hash::Hash,
    {
        if self.len() == 0 {
            panic("cannot increment a counter inside an empty slice of counters");
        }

        let i = fxhash::hash(x) % self.len();
        self[i].increment();
    }
}

#[cold]
#[inline(never)]
#[track_caller]
#[allow(dead_code)]
fn panic(msg: &str) -> ! {
    panic!("{msg}");
}

/// Register the given counters with the `SanitizerCoverage` consumer.
///
/// The `SanitizerCoverage` API unfortunately does not provide any method of
/// unregistering counters, so the given `counters` slice must be `'static`.
///
/// # Example
///
/// ```
/// use sancov::Counter;
///
/// static COUNTERS: [Counter; 4096] = [Counter::new(); 4096];
///
/// sancov::register_counters(&COUNTERS);
/// #
/// # #[no_mangle]
/// # pub fn __sanitizer_cov_8bit_counters_init(_: *const u8, _: *const u8) {}
/// ```
pub fn register_counters(counters: &'static [Counter]) {
    unsafe {
        let start = counters.as_ptr() as *const u8;
        let end = start.add(counters.len()) as *const u8;
        sys::__sanitizer_cov_8bit_counters_init(start, end);
    }
}

#[cfg(test)]
#[no_mangle]
pub fn __sanitizer_cov_8bit_counters_init(_: *const u8, _: *const u8) {}
