#!/usr/bin/env bash
# Tags: no-tsan, no-asan, no-msan, no-ubsan, no-fasttest, no-debug, no-llvm-coverage
#       ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
# NOTE: jemalloc is disabled under sanitizers

CURDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=../shell_config.sh
. "$CURDIR"/../shell_config.sh

${CLICKHOUSE_CLIENT} --jemalloc_enable_profiler=1 -q "SELECT number FROM numbers(1000000) ORDER BY number FORMAT Null";

# Check that system.jemalloc_profile returns data with all output formats
# Always use fast symbolization mode for performance
echo "Testing raw format:"
${CLICKHOUSE_CLIENT} -q "SELECT count() > 0 FROM system.jemalloc_profile SETTINGS jemalloc_profile_output_format = 'raw'";

echo "Testing symbolized format:"
${CLICKHOUSE_CLIENT} -q "SELECT count() > 0 FROM system.jemalloc_profile SETTINGS jemalloc_profile_output_format = 'symbolized', jemalloc_profile_symbolization_mode = 'fast'";
