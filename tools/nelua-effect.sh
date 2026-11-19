#!/bin/sh
set -eu
compiler=$1
cache=$2
source=$3
output=$4
raw=$(mktemp "${output}.XXXXXXXX.c")
trap 'rm -f "$raw"' EXIT
"$compiler" --code --cache-dir "$cache" -o "$raw" "$source"

# Bend splices multiple compiler outputs into one C translation unit.
# Their common Nelua nil type must be defined only once.
sed '/^typedef struct nlniltype {} nlniltype;$/ {
    i\
#ifndef IROH_NELUA_NILTYPE\
#define IROH_NELUA_NILTYPE
    a\
#endif
}' "$raw" > "$output"
