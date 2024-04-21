#!/bin/sh
set -ex
git config --global --add safe.directory "$PWD"
pre-commit run --all-files --show-diff-on-failure
