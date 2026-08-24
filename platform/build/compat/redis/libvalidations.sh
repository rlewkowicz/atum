#!/usr/bin/env bash

is_boolean_yes() {
  case "${1,,}" in
    1|true|yes|y|on) return 0 ;;
    *) return 1 ;;
  esac
}
