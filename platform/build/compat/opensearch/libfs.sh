#!/usr/bin/env bash

is_dir_empty() {
  local atum_dir="$1"

  [[ -d "$atum_dir" ]] || return 0
  [[ -z "$(find "$atum_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]]
}
