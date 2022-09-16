#![no_std]

extern "C" {
    pub fn __sanitizer_cov_8bit_counters_init(start: *const u8, end: *const u8);
}
