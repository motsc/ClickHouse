# Fuzzing Bug Tally

All bugs discovered via libFuzzer + ASan build targeting ClickHouse deserialization
and compression codec code paths. Discovered March 2026.

---

## PR 1: Compression Codec Memory Safety (T64, Multiple)

**Severity:** Critical — heap-buffer-overflow + process abort in decompression
**Commit:** `3b97943749e`
**Files:** `src/Compression/CompressionCodecT64.cpp`, `src/Compression/CompressionCodecMultiple.cpp`

### Bug 1a: T64 — missing `bytes_size >= bytes_to_skip` check
- **Location:** `CompressionCodecT64::doDecompressData`, early `memcpy` for skipping bytes
- **Type:** Heap-buffer-overflow (read past source buffer)
- **Trigger:** Compressed payload shorter than the `bytes_to_skip` header field
- **Crash reproducer:** 10 bytes: `85 68 85 3b 8d 85 0a fd 81 2c`

### Bug 1b: T64 — missing `bytes_size >= header_size` (16 bytes) check
- **Location:** `CompressionCodecT64::doDecompressData`, `memcpy` for min/max header
- **Type:** Heap-buffer-overflow (OOB read of min/max values)
- **Trigger:** Any input shorter than 16 bytes

### Bug 1c: Multiple — reversed `PODArray` range causing ~2^64 allocation
- **Location:** `CompressionCodecMultiple::doDecompressData`
- **Type:** Process abort via `std::bad_alloc` / allocator abort
- **Trigger:** `compression_methods_size + 1 > source_size`; unsigned arithmetic produces
  reversed `[&source[n+1], &source[m])` where `n >= m`, resulting in ~2^64 byte PODArray
- **Crash reproducer:** 9 bytes: `00 00 00 00 00 00 db 00 9a`

### Bug 1d: Multiple — OOB read before 9-byte header check
- **Location:** `CompressionCodecMultiple::doDecompressData`, `readDecompressedBlockSize`
- **Type:** Heap-buffer-overflow (reads `source[5..8]`)
- **Trigger:** Any input shorter than 9 bytes (`COMPRESSED_BLOCK_HEADER_SIZE`)

---

## PR 2: FPC Codec — Attacker-Controlled OOM

**Severity:** High — OOM (DoS) via 4 GiB allocation bypassing MemoryTracker
**Commit:** `c84f1b32bf3`
**File:** `src/Compression/CompressionCodecFPC.cpp`

### Bug 2: FPC — `compressed_level` controls `2 * (1 << level) * sizeof(T)` allocation
- **Location:** `CompressionCodecFPC::doDecompressData`, `FPCOperation` constructor
- **Type:** OOM — `std::vector` allocation bypasses `MemoryTracker`
- **Trigger:** Byte 1 of payload set to 28; two `Float64` predictor tables = `2 * 2^28 * 8 = 4 GiB`
- **Fix:** Added 256 MiB cap check after existing level-validity check; same cap applied
  to `Float32` path

---

## PR 3: SerializationVariant — Unchecked Discriminator OOB Write

**Severity:** Critical — heap-buffer-overflow and `__libcpp_verbose_abort` in libc++
**Commits:** `c84f1b32bf3`, `0d42eb9c2dc`, `69f92f1b5bb`
**File:** `src/DataTypes/Serializations/SerializationVariant.cpp`

### Bug 3a: Discriminator used as unchecked index into `variant_rows_offsets[]`
- **Location:** BASIC mode loop (lines 596-597), COMPACT PLAIN loop (lines 772-781)
- **Type:** Heap-buffer-overflow in hardened libc++ (`_LIBCPP_HARDENING_MODE_FAST`
  calls `__libcpp_verbose_abort` on OOB vector access → `abort()`)
- **Trigger:** Any discriminator byte ≥ num_variants in the deserialized stream
- **Fix:** Added explicit `INCORRECT_DATA` bounds check before all 6 access sites

### Bug 3b: `compact_discr` used as unchecked index in COMPACT granule
- **Location:** `SerializationVariant.cpp` COMPACT granule block (line 806 area)
- **Type:** Same as 3a; `state.compact_discr` read from stream via
  `readDiscriminatorsGranuleStart` with no bounds check in the caller
- **Fix:** Bounds check moved into the COMPACT processing block of
  `deserializeBinaryBulkWithMultipleStreams` (the `static` method can't access
  `variant_serializations`)

### Bug 3c: Unsigned underflow in partial compact discriminator read
- **Location:** `SerializationVariant::deserializeCompactDiscriminators` lambda
- **Type:** UB — `discriminators_data.size() - limit_in_granule` underflows when
  `SerializationNumber::deserializeBinaryBulk` reads fewer rows than requested
  on truncated input
- **Fix:** Added explicit `actual_rows_read < limit_in_granule` guard before
  the subtraction

---

## PR 4: Systematic LOGICAL_ERROR → INCORRECT_DATA in Deserialization Paths

**Severity:** High — fuzzer abort on any of ~35 data-dependent throw sites
**Commits:** `c84f1b32bf3`, `69f92f1b5bb`, `9972977047e`, `c4b9faa3a22`, `0858fc45b23`
**Files:** Multiple serialization files (see below)

**Root cause:** In ASan/fuzzer builds, `LOGICAL_ERROR` calls `abortOnFailedAssertion`
→ `abort()` before the exception propagates to the fuzzer's `catch(...)`. Any
condition reachable from malformed binary input must use `INCORRECT_DATA`.

| File | Sites fixed | Condition |
|------|-------------|-----------|
| `NativeReader.cpp` | 1 | row count mismatch after deserialization |
| `SerializationNullable.cpp` | 1 | null map / nested column size mismatch |
| `SerializationTuple.cpp` | 1 | tuple element size mismatch after deserialization |
| `SerializationArray.cpp` | 1 | elements column longer than last offset |
| `SerializationSparse.cpp` | 1 | inconsistent offsets/values sizes |
| `SerializationLowCardinality.cpp` | 1 | non-UInt index column type |
| `ColumnUnique.h` | 2 | null in non-nullable dictionary; index out of range |
| `ColumnVariant.cpp` | 3 | `validateState`: discriminators/offsets size mismatch; offset past end; variant size mismatch |
| `SerializationVariant.cpp` | 2 | null variant column pointer; variant size < limit |
| `SerializationVariantElement.cpp` | 1 | deserialized column size < expected limit |
| `SerializationString.cpp` | 1 | empty data stream |
| `SerializationObject.cpp` | 3 | empty stream + size mismatches in STRING/typed/dynamic paths |
| `SerializationObjectSharedData.cpp` | ~20 | empty streams, row-count mismatches, path-not-found across 4 deserialization functions |
| `SerializationReplicated.cpp` | 3 | `num_rows != limit`; invalid `size_of_indexes_type`; missing elements substream |

---

## PR 5: SerializationLowCardinality — Heap-Buffer-Overflow in Additional Keys

**Severity:** Critical — heap-buffer-overflow (ASan) + OOM
**Commits:** `95019c9c005`, `bef7b3d18ad`, `f18e5e12f39`
**File:** `src/DataTypes/Serializations/SerializationLowCardinality.cpp`

### Bug 5a: `additional_keys->index()` with out-of-range position (heap-buffer-overflow)
- **Location:** `mapIndexWithAdditionalKeys` → `additional_keys->index(*maps.additional_keys_map, 0)`
- **Type:** Heap-buffer-overflow — `ColumnString::sizeAt` reads past end of offsets array
- **Root cause:** `add_keys_data[overflow_map[i]] = T(i)` stores the original shifted
  position `i` (up to `overflow_map_size - 1`) as the value, not a compact sequential index.
  The check `cur_overflowed_pos <= additional_keys->size()` passed (1 ≤ 1) but
  `add_keys_data[0] = overflow_map_size - 1 = 122` caused `sizeAt(122)` on a 1-entry column.
- **Fix (first attempt):** Checked `cur_overflowed_pos` — incorrect; this is the count,
  not the max position.
- **Fix (final):** Return `overflow_map_size` as `required_additional_keys` (the actual
  maximum index stored in `additional_keys_map`).

### Bug 5b: `overflow_map` allocation with attacker-controlled size (OOM)
- **Location:** `PaddedPODArray<T> overflow_map(overflow_map_size, 0)` in
  `mapIndexWithAdditionalKeys`
- **Type:** `allocation-size-too-big` (ASan) — `overflow_map_size = max_value - dict_size + 1`
  where `max_value` is the largest deserialized index value
- **Trigger:** Single UInt64 index entry set to `dict_size + 2^63` forces
  `2^63 * sizeof(UInt64)` byte `PaddedPODArray` allocation bypassing `MemoryTracker`
- **Fix:** `MAX_OVERFLOW_MAP_SIZE = 1 << 20` cap before allocation; throw `INCORRECT_DATA`
  if exceeded

---

## PR 6: BlockInfo — Attacker-Controlled OOM via `out_of_order_buckets`

**Severity:** High — OOM (DoS) bypassing MemoryTracker
**Commit:** `6eb2eee2f84`
**File:** `src/Core/BlockInfo.cpp`

### Bug 6: `out_of_order_buckets` field reads attacker-controlled size via generic `readBinary<vector>`
- **Location:** `BlockInfo::read`, field 3 (`out_of_order_buckets`)
- **Type:** OOM — `std::vector::resize(attacker_controlled)` bypasses `MemoryTracker`
- **Trigger:** `DEFAULT_MAX_STRING_SIZE = 1 GiB / 4 = 268M` entries allowed; at 200M entries
  = ~800 MiB allocation; libFuzzer OOM fires at ~767 MB RSS
- **Fix:** Expanded field 3 outside `READ_FIELD` macro with explicit `readVarUInt` + 65536
  entry cap (`MAX_OUT_OF_ORDER_BUCKETS`). Two-level aggregation uses at most 256 buckets.

---

## PR 7: Allocator — LOGICAL_ERROR for Attacker-Controlled Size

**Severity:** Medium — fuzzer abort (covered by PR 4, but logically separate)
**Commit:** `69f92f1b5bb`
**File:** `src/Common/Allocator.cpp`

### Bug 7: `checkSize` throws `LOGICAL_ERROR` for sizes ≥ 2^63
- **Location:** `Allocator::checkSize`
- **Type:** Fuzzer abort via `abortOnFailedAssertion`
- **Trigger:** Malformed `LowCardinality(String)` deserialization produces an
  oversized string length; `checkSize` detects it but calls `abort()` instead of
  throwing a catchable exception
- **Fix:** Changed from `LOGICAL_ERROR` to `CANNOT_ALLOCATE_MEMORY`

---

## PR Branches (all local, not yet pushed)

| PR | Branch | Files changed | Bugs | PR link |
|----|--------|--------------|------|---------|
| PR-A | `fix/t64-multiple-decompress-oob` | `CompressionCodecT64.cpp`, `CompressionCodecMultiple.cpp` | 1a, 1b, 1c, 1d | TBD |
| PR-B | `fix/fpc-predictor-oom` | `CompressionCodecFPC.cpp` | 2 | TBD |
| PR-C | `fix/serialization-variant-discriminator-oob` | `SerializationVariant.cpp`, `SerializationVariantElement.cpp`, `ColumnVariant.cpp` | 3a, 3b, 3c | TBD |
| PR-D | `fix/deserialization-logical-error-abort` | `NativeReader.cpp`, `SerializationNullable.cpp`, `SerializationTuple.cpp`, `SerializationArray.cpp`, `SerializationSparse.cpp`, `SerializationString.cpp`, `SerializationObject.cpp`, `SerializationObjectSharedData.cpp`, `SerializationReplicated.cpp`, `ColumnUnique.h`, `Allocator.cpp` | 4, 7 | TBD |
| PR-E | `fix/lc-additional-keys-oob-oom` | `SerializationLowCardinality.cpp` | 5a, 5b | TBD |
| PR-F | `fix/blockinfo-buckets-oom` | `BlockInfo.cpp` | 6 | TBD |

---

## Stats

- **Total bugs found:** 14 distinct vulnerabilities across 7 areas
- **Critical (memory safety / process abort):** 8 (1a, 1b, 1c, 2, 3a, 3b, 5a, and the LOGICAL_ERROR category)
- **High (OOM / DoS):** 4 (1c, 2, 5b, 6)
- **Fuzzers used:** `compression_chain_fuzzer`, `nested_type_serialization_fuzzer`,
  `serialization_variant_fuzzer`, `native_reader_fuzzer`, `aggregate_function_state_deserialization_fuzzer`
- **Total fuzzer exec:** >5M iterations across all runs
