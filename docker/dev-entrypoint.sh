#!/bin/sh
set -eu

exec cargo watch -x "run --locked -p betterbase-accounts-server"
