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
# Share the nil type and give each effect file its own generated helpers
# and array types.
namespace=$(basename "$source" .nelua | tr -c '[:alnum:]_' '_' | sed 's/_$//')
sed -E -e "s/(^|[^[:alnum:]_])(nelua_[[:alnum:]_]+|nl[[:alnum:]_]*_arr[0-9]+[[:alnum:]_]*)/\1iroh_${namespace}_\2/g" -e '/^typedef struct nlniltype \{\} nlniltype;$/ {
    i\
#ifndef IROH_NELUA_NILTYPE\
#define IROH_NELUA_NILTYPE
    a\
#endif
}' "$raw" > "$output"
