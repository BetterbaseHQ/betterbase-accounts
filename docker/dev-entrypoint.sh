#!/bin/sh
set -eu

exec cargo watch -x "run --locked -p less-accounts-server"
