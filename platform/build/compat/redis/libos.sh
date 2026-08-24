#!/usr/bin/env bash

retry_while() {
  local atum_command="$1"
  local atum_retries="${2:-12}"
  local atum_delay="${3:-5}"
  local atum_attempt=1

  until eval "$atum_command"; do
    (( atum_attempt >= atum_retries )) && return 1
    sleep "$atum_delay"
    ((atum_attempt++))
  done
}
