# Fuzzing Session Learnings

## Build Infrastructure

### Direct compile (bypass ninja)
Ninja segfaults on 69 MB `build.ninja`. Use direct compile via extracted flags:
- Script: `tmp/gen_compile_script.py` → `tmp/direct_compile_fuzzers.sh`
- Script: `tmp/patch_dbms.sh` recompiles patched source files and updates `.a` archives
- Script: `tmp/rebuild_datatype_fuzzers.sh` = patch_dbms.sh + re-link DataType fuzzers

### Archive locations
- `libdbms.a` — most serialization code (`SerializationVariant`, `SerializationNullable`, `SerializationTuple`, etc.)
- `libclickhouse_common_io.a` — `Allocator.cpp`, I/O helpers
- `libclickhouse_compression.a` — compression codecs (was missing; built from `.o` files)
- `libclickhouse_aggregate_functions.a` — needed by DataTypes fuzzers (not compression fuzzers)

### Re-link workflow after patching a source file
1. Recompile the `.cpp.o` using flags from `patch_dbms.sh`
2. Update the archive: `llvm-ar-21 r <archive>.a <file>.cpp.o && llvm-ranlib-21 <archive>.a`
3. Re-link the fuzzer binary using flags from `direct_compile_fuzzers.sh`

## LOGICAL_ERROR → abort() pattern
In ASan/fuzzer builds, `LOGICAL_ERROR` calls `abortOnFailedAssertion` → `abort()` before
the exception propagates to the fuzzer's `catch(...)`. Any data-dependent check must use
`INCORRECT_DATA` (or another non-LOGICAL_ERROR code) instead.

### `native_format` conditional anti-pattern
Many serialization files used:
```cpp
throw Exception(settings.native_format ? ErrorCodes::INCORRECT_DATA : ErrorCodes::LOGICAL_ERROR, ...);
```
Non-native format paths are also reachable from malformed binary input. All such conditionals
must be changed to unconditionally use `INCORRECT_DATA`.

Files fixed: `SerializationNullable.cpp:162`, `SerializationTuple.cpp:834`, `SerializationVariant.cpp:650`

## SerializationVariant-specific fixes

### Offset fill loop bounds check (line ~712)
`discr` from deserialized bytes can be >= `variant_serializations.size()`. In hardened libc++
(`_LIBCPP_HARDENING_MODE_FAST`), vector OOB access calls `__libcpp_verbose_abort` → `abort()`.
Fix: explicit bounds check before `variant_offsets[discr]++`.

### Compact discriminator partial read underflow (line ~785)
`SerializationNumber::deserializeBinaryBulk` reads only available bytes. If fewer than
`limit_in_granule` rows are in the stream, `discriminators_data.size() - limit_in_granule`
underflows (unsigned arithmetic). Fix: compare `actual_rows_read < limit_in_granule` first.

## Allocator.cpp
`checkSize` threw `LOGICAL_ERROR` for sizes >= 2^63. This fires when malformed
`LowCardinality(String)` input produces an attacker-controlled string length.
Changed to `CANNOT_ALLOCATE_MEMORY`.

## Fuzzer exec rates (30s smoke tests, ASan build, ARM64)
- `compression_chain_fuzzer`: ~4,456 exec/s (stable)
- `nested_type_serialization_fuzzer`: ~2,054 exec/s (stable after Allocator fix)
- `serialization_variant_fuzzer`: ~2,970 exec/s (stable after multiple fixes)
