"""Regenerate src/idna_data.bend from the Unicode 18.0.0 data files.

Pass a directory containing the four files (basenames below) from
https://www.unicode.org/Public/18.0.0/{idna,ucd,ucd/extracted}/.
The generated lookup tables and their inputs are covered by LICENSE-UNICODE.
"""
import argparse
import hashlib
import itertools
from functools import cache
from pathlib import Path

HASHES = {
    "IdnaMappingTable.txt": "a03b1eb38032268c696406a83f0972d6a815acd2c8d4151d42ec0fda70ffced1",
    "UnicodeData.txt": "0736451de439ae7baf1425136617da495e09ee5afbe6e394374db7009ea08950",
    "DerivedNormalizationProps.txt": "98ac7f67d985fe781e317f6182e885e94cabb0c314769e6dd73e48b226931ccd",
    "DerivedJoiningType.txt": "e2408ff2c92b175b0f7bf62c989bbb54c7b077528fe31f8d69b96fa09e7d61ed",
}
LIMIT = 0x110000
SEQUENCE = 0x120000
PAGE = 32
OFFSET = 0x4000
BIDI = {"L": 1, "R": 2, "AL": 2, "EN": 3, "AN": 4, "NSM": 5,
        **dict.fromkeys(("ES", "CS", "ET", "ON", "BN"), 6)}
JOIN = {"L": 1, "R": 2, "D": 3, "T": 4}


def rows(folder, name):
    raw = (folder / name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != HASHES[name]:
        raise ValueError(f"Expected Unicode 18.0.0 {name}")
    for line in raw.decode("utf-8").splitlines():
        content = line.partition("#")[0].strip()
        if content:
            yield [field.strip() for field in content.split(";")]


def interval(field):
    ends = [int(item, 16) for item in field.split("..")]
    return range(ends[0], ends[-1] + 1)


def split_word(value):
    assert 0 <= value < 1 << 24
    return chr(OFFSET + (value >> 12)) + chr(OFFSET + (value & 4095))


def run_page(values):
    # Exclusive end and a 24-bit word. Each character is a printable BMP scalar.
    end = 0
    result = []
    for word, group in itertools.groupby(values):
        end += len(list(group))
        result.append(chr(OFFSET + end) + split_word(word))
    return "".join(result)


def dispatch(out, name, strings):
    # Keep Bend's generated match functions small regardless of the database size.
    if len(strings) > PAGE:
        groups = [strings[i:i + PAGE] for i in range(0, len(strings), PAGE)]
        subnames = []
        for index, group in enumerate(groups):
            subname = f"{name}_{index}"
            dispatch(out, subname, group)
            subnames.append(subname)
        out.append(f"def {name}_group(group: U32, i: U32) -> String:\n  match group:")
        out.extend(f"    case {i}:\n      {sub}(i)" for i, sub in enumerate(subnames[:-1]))
        out.append(f"    case _:\n      {subnames[-1]}(i)\n")
        out.append(f"def {name}(+i: U32) -> String:\n  {name}_group(U32.shrn(i,5n),U32.and(i,31))\n")
    elif len(strings) == 1:
        out.append(f'def {name}(i: U32) -> String:\n  "{strings[0]}"\n')
    else:
        out.append(f"def {name}(i: U32) -> String:\n  match i:")
        out.extend(f'    case {i}:\n      "{s}"' for i, s in enumerate(strings[:-1]))
        out.append(f'    case _:\n      "{strings[-1]}"\n')


def emit_trie(out, name, vector):
    # Each level maps five bits to a unique page in the level below.
    levels = []
    while len(vector) > 1:
        pages = {}
        indices = []
        for i in range(0, len(vector), PAGE):
            page = tuple(vector[i:i + PAGE])
            indices.append(pages.setdefault(page, len(pages)))
        bank = f"{name}{len(levels)}"
        dispatch(out, bank, [run_page(page) for page in pages])
        levels.append(bank)
        vector = indices
    expression = "0"
    for depth, bank in reversed(list(enumerate(levels))):
        index = f"U32.and(U32.shrn(cp,{depth * 5}n),31)" if depth else "U32.and(cp,31)"
        expression = f"U.range_word({bank}({expression}),{index})"
    out.append(f"def {name}(+cp: U32) -> U32:\n  {expression}\n")


def generate(folder, output):
    props = [0] * LIMIT
    decomposition = {}
    start = 0
    for row in rows(folder, "UnicodeData.txt"):
        cp = int(row[0], 16)
        if row[1].endswith(", First>"):
            start = cp
            continue
        begin = start if row[1].endswith(", Last>") else cp
        prop = int(row[3]) | (row[2].startswith("M") << 8) | (BIDI.get(row[4], 0) << 9)
        props[begin:cp + 1] = [prop] * (cp + 1 - begin)
        if row[5] and not row[5].startswith("<"):
            decomposition[cp] = tuple(int(s, 16) for s in row[5].split())
    for bounds, joining, *_ in rows(folder, "DerivedJoiningType.txt"):
        for cp in interval(bounds):
            props[cp] |= JOIN.get(joining, 0) << 12
    excluded = set()
    for bounds, prop, *_ in rows(folder, "DerivedNormalizationProps.txt"):
        if prop == "Full_Composition_Exclusion":
            excluded.update(interval(bounds))

    @cache
    def decompose(cp):
        if cp in decomposition:
            return tuple(child for part in decomposition[cp] for child in decompose(part))
        return (cp,)

    mapping = [1] * LIMIT
    sequence_offsets = {}
    flat = []
    for bounds, status, *fields in rows(folder, "IdnaMappingTable.txt"):
        if status == "disallowed":
            continue
        replacement = tuple(int(s, 16) for s in fields[0].split()) if status == "mapped" else ()
        for cp in interval(bounds):
            if status == "ignored":
                mapping[cp] = 2
                continue
            parts = replacement if status == "mapped" else (cp,)
            if len(parts) == 1 and parts[0] not in decomposition:
                nfd = parts
            else:
                nfd = tuple(child for part in parts for child in decompose(part))
            if len(nfd) == 1:
                delta = (nfd[0] - cp) % LIMIT
                mapping[cp] = 3 + delta if delta else 0
            else:
                if nfd not in sequence_offsets:
                    sequence_offsets[nfd] = len(flat)
                    flat.extend(nfd)
                mapping[cp] = SEQUENCE + (len(nfd) << 16) + sequence_offsets[nfd]
    assert len(flat) < 65536
    buckets = [[] for _ in range(512)]
    for cp, parts in decomposition.items():
        if len(parts) == 2 and cp not in excluded:
            a, b = parts
            buckets[((a * 31) ^ b) & 511].extend((a, b, cp))

    out = ["# Generated by tools/generate_idna.py. Unicode 18.0.0, see LICENSE-UNICODE.",
           "import Base\nimport ./idna_table.bend as U\n"]
    emit_trie(out, "mapping", mapping)
    emit_trie(out, "properties", props)
    dispatch(out, "sequence_page", ["".join(map(split_word, flat[i:i + PAGE])) for i in range(0, len(flat), PAGE)])
    dispatch(out, "composition_bucket", ["".join(map(split_word, bucket)) for bucket in buckets])
    output.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("unicode_dir", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    generate(args.unicode_dir, args.output)
