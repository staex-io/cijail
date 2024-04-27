#!/bin/sh

clean() {
    rm -rf tests/keys
    find target -type f -name '*.profraw' -delete || true
}

# shellcheck disable=SC1091
test_coverage_preamble() {
    cargo llvm-cov show-env --export-prefix >.llvm-cov-env
    . ./.llvm-cov-env
    # clean old coverage data
    cargo llvm-cov clean --workspace
}

test_coverage_postamble() {
    # produce coverage report in lcov format
    cargo llvm-cov report --lcov --output-path cijail.lcov
    rm -rf --one-file-system coverage
    # produce coverage report in html format
    cargo llvm-cov report --html --output-dir coverage
    # print coverage report in the terminal
    cargo llvm-cov report
    # convert to xml format to see coverage in gitlab
    lcov_cobertura cijail.lcov
    # output coverage summary for gitlab parsing
    lcov --summary cijail.lcov
}

test_all() {
    # compile everything
    cargo test --quiet --no-run
    ./target/debug/cijail --version
    ldd ./target/debug/cijail
    ./target/debug/cijail sh -c 'head -n1 /etc/passwd'
    # run all tests
    cargo test --no-fail-fast -- --nocapture
}

set -ex
clean
test_coverage_preamble
test_all
test_coverage_postamble
