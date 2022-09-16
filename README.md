<div align="center">

  <h1><code>sancov</code></h1>

  <p><strong>Rust bindings to LLVM's <code>SanitizerCoverage</code> interface.</strong></p>

  <a href="https://github.com/rust-fuzz/sancov/actions?query=workflow%3ARust"><img alt="GitHub Actions Status" src="https://github.com/rust-fuzz/sancov/workflows/Rust/badge.svg"/></a>
  <a href="https://docs.rs/sancov"><img src="https://docs.rs/sancov/badge.svg" alt="Documentation Status" /></a>

</div>

## About

Rust bindings to [LLVM's `SanitizerCoverage`
interface](https://clang.llvm.org/docs/SanitizerCoverage.html).

Using these bindings allows you to convey additional coverage information to the
`SanitizerCoverage` consumer, which is typically a fuzzer like `libFuzzer`. You
can, for example, convey edge coverage information inside JIT code or which size
classes are being allocated from in your custom allocator that would otherwise
not be made visible by LLVM's inserted coverage instrumentation.

## Example

```rust,no_run
use sancov::Counters;

// Define a bunch of counters.
static COUNTERS: Counters<4096> = Counters::new();

// Register the counters with the `SanitizerCoverage` consumer.
COUNTERS.register();

// Increment a counter when some custom code is executed!
COUNTERS[42].increment()
```
