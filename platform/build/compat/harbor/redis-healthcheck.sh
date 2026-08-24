#!/bin/sh

set -eu

atum_ping="$(redis-cli -h 127.0.0.1 ping)"
[ "$atum_ping" = PONG ]
