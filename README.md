<div align="center">

  <h1><code>sancov</code></h1>

  <p><strong>Rust bindings to LLVM's `SanitizerCoverage` interface.</strong></p>

  <img alt="GitHub Actions Status" src="https://github.com/rust-fuzz/sancov/workflows/Rust/badge.svg"/>

</div>

# About

Rust bindings to LLVM's `SanitizerCoverage` interface. Using these bindings
allows you to convey additional coverage information to the `SanitizerCoverage`
consumer, which is typically a fuzzer like `libFuzzer`. You can, for example,
convey coverage information inside JIT code for you language runtime or which
size classes are being allocated from in your custom allocator.
