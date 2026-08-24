#!/usr/bin/env bash

replace_in_file() {
  local atum_file="$1"
  local atum_pattern="$2"
  local atum_replacement="$3"
  local atum_global="${4:-true}"
  local atum_suffix=

  [[ "$atum_global" == true ]] && atum_suffix=g
  sed -i -E "s|${atum_pattern}|${atum_replacement}|${atum_suffix}" "$atum_file"
}
