#!/usr/bin/env sh

# Static analysis is deliberately report-oriented: existing findings are
# preserved in build/test/static-analysis instead of being hidden or changing
# production sources as part of a test run.
set -u

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
report_dir="$root_dir/build/test/static-analysis"
mkdir -p "$report_dir"

status=0
source_files=$(find "$root_dir/lib" "$root_dir/main" -type f -name '*.c' \
    ! -name '*.bpf.c' -print)

if command -v cppcheck >/dev/null 2>&1; then
    cppcheck \
        --enable=warning,performance,portability \
        --inconclusive \
        --inline-suppr \
        --suppress=missingIncludeSystem \
        -I"$root_dir" -I"$root_dir/lib" -I"$root_dir/main" \
        $source_files \
        >"$report_dir/cppcheck.stdout" 2>"$report_dir/cppcheck.txt" || status=1
else
    printf '%s\n' 'SKIP: cppcheck is not installed' >"$report_dir/cppcheck.txt"
fi

if command -v gcc >/dev/null 2>&1; then
    # GCC's path-sensitive analyzer complements cppcheck; do not link or run
    # constructor code while scanning.
    gcc -std=gnu11 -D_GNU_SOURCE -fanalyzer -fsyntax-only \
        -I"$root_dir" -I"$root_dir/lib" -I"$root_dir/main" \
        $source_files \
        >"$report_dir/gcc-fanalyzer.stdout" 2>"$report_dir/gcc-fanalyzer.txt" || status=1
else
    printf '%s\n' 'SKIP: gcc is not installed' >"$report_dir/gcc-fanalyzer.txt"
fi

if command -v clang >/dev/null 2>&1; then
    clang --analyze --analyzer-output=text -std=gnu11 -D_GNU_SOURCE \
        -I"$root_dir" -I"$root_dir/lib" -I"$root_dir/main" \
        $source_files \
        >"$report_dir/clang-analyzer.stdout" 2>"$report_dir/clang-analyzer.txt" || status=1
else
    printf '%s\n' 'SKIP: clang is not installed' >"$report_dir/clang-analyzer.txt"
fi

if command -v clang-tidy >/dev/null 2>&1; then
    clang-tidy --checks='clang-analyzer-*,bugprone-*,performance-*' \
        $source_files -- \
        -std=gnu11 -D_GNU_SOURCE -I"$root_dir" -I"$root_dir/lib" -I"$root_dir/main" \
        >"$report_dir/clang-tidy.stdout" 2>"$report_dir/clang-tidy.txt" || status=1
else
    printf '%s\n' 'SKIP: clang-tidy is not installed' >"$report_dir/clang-tidy.txt"
fi

if command -v valgrind >/dev/null 2>&1 && [ -x "$root_dir/build/test/test_lib" ]; then
    NETFAST_TEST_NO_AUTO_INIT=1 valgrind --leak-check=full --show-leak-kinds=all \
        --errors-for-leak-kinds=definite --error-exitcode=1 \
        "$root_dir/build/test/test_lib" \
        >"$report_dir/valgrind.stdout" 2>"$report_dir/valgrind.txt" || status=1
else
    printf '%s\n' 'SKIP: valgrind or test_lib is unavailable' >"$report_dir/valgrind.txt"
fi

printf 'Static-analysis reports: %s\n' "$report_dir"
exit "$status"
