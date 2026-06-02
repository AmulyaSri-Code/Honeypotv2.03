#!/bin/sh
set -eu

mkdir -p /app/data /app/logs
chown -R honeypot:honeypot /app/data /app/logs

exec gosu honeypot "$@"
