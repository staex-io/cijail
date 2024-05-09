#!/bin/sh
set -e
cargo deny check --disable-fetch || true
