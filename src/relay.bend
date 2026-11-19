import Base

# Binary WebSocket messages after relay authentication (Iroh v1.5.0).
# Payload bytes remain available for the datagram or endpoint decoder.
type Direction is Data:
  ToRelay{}
  ToClient{}

type Version is Data:
  V1{}
  V2{}

type Frame is Data:
  Message{tag: U32, payload: List<&2, U32>}
  BadByte{}
  TruncatedTag{}
  UnknownTag{}
  DisallowedTag{}
  InvalidLength{}
  InvalidUtf8{}
  Oversized{}

type Size is Data:
  Length{value: U32}
  NonByte{}
  TooLarge{}

def measure_go(bytes: List<&2, U32>, +size: U32, byte_ok: Bool, room: Bool) -> Size:
  match bytes byte_ok room:
    case _ False{} _:
      NonByte{}
    case _ _ False{}:
      TooLarge{}
    case Nil{} True{} True{}:
      Length{size}
    case Con{byte, tail} True{} True{}:
      measure_go(tail, U32.inc(size), U32.is_le(byte, 255), U32.is_lt(size, 65544))

def measure(bytes: List<&2, U32>, size: U32) -> Size:
  measure_go(bytes, size, True{}, True{})

type Header is Data:
  Tag{value: U32, width: U32, payload: List<&2, U32>}
  Incomplete{}

def read_tag(+remaining: Nat, +width: U32, bytes: List<&2, U32>, +value: U32) -> Header:
  match remaining bytes:
    case 0n _:
      Tag{value, width, bytes}
    case 1n+rest Nil{}:
      Incomplete{}
    case 1n+rest Con{byte, tail}:
      # No defined relay tag exceeds 13. Cap the accumulator to prevent
      # wrapping while still consuming the entire QUIC varint.
      read_tag(rest, width, tail, U32.add(U32.shln(U32.min(value, 64), 8n), byte))

def tag_width(+prefix: U32, bits: U32, tail: List<&2, U32>) -> Header:
  match prefix:
    case 0:
      Tag{bits, 1, tail}
    case 1:
      read_tag(1n, 2, tail, bits)
    case 2:
      read_tag(3n, 4, tail, bits)
    case _:
      read_tag(7n, 8, tail, bits)

def split_tag(bytes: List<&2, U32>) -> Header:
  match bytes:
    case Nil{}:
      Incomplete{}
    case Con{+head, tail}:
      tag_width(U32.shrn(head, 6n), U32.and(head, 63), tail)

def sender_limit(dir: Direction, packet: U32, +payload: U32) -> Bool:
  match dir:
    case ToRelay{}:
      U32.is_le(packet, 65536)
    case ToClient{}:
      U32.is_le(payload, 65536)

def allowed(dir: Direction, ver: Version, +tag: U32) -> Bool:
  match dir ver:
    case ToRelay{} _:
      U32.is_eq(tag, 4) || U32.is_eq(tag, 5) || U32.is_eq(tag, 9) || U32.is_eq(tag, 10)
    case ToClient{} V1{}:
      U32.is_ge(tag, 6) && U32.is_le(tag, 12)
    case ToClient{} V2{}:
      U32.is_ge(tag, 6) && U32.is_le(tag, 13) && Bool.not(U32.is_eq(tag, 11))

def valid_length(+tag: U32, +len: U32) -> Bool:
  match tag:
    case 4:
      U32.is_ge(len, 33)
    case 5:
      U32.is_ge(len, 35)
    case 6:
      U32.is_ge(len, 33)
    case 7:
      U32.is_ge(len, 35)
    case 8:
      U32.is_eq(len, 32)
    case 9:
      U32.is_eq(len, 8)
    case 10:
      U32.is_eq(len, 8)
    case 11:
      True{}
    case 12:
      U32.is_eq(len, 8)
    case _:
      U32.is_ge(len, 1)

# RFC 3629 continuation bounds also reject overlong sequences, surrogates,
# and code points above U+10FFFF.
type Utf8 is Data:
  Lead{}
  Continuation{remaining: U32, low: U32, high: U32}
  Invalid{}

def first_continuation(+lead: U32, count: U32) -> Utf8:
  match lead:
    case 224:
      Continuation{count, 160, 191}
    case 237:
      Continuation{count, 128, 159}
    case 240:
      Continuation{count, 144, 191}
    case 244:
      Continuation{count, 128, 143}
    case _:
      Continuation{count, 128, 191}

def utf8_lead(byte: U32, ascii: Bool, two: Bool, three: Bool, four: Bool) -> Utf8:
  match ascii two three four:
    case True{} _ _ _:
      Lead{}
    case _ True{} _ _:
      Continuation{1, 128, 191}
    case _ _ True{} _:
      first_continuation(byte, 2)
    case _ _ _ True{}:
      first_continuation(byte, 3)
    case _ _ _ _:
      Invalid{}

def utf8_next(+left: U32, inside: Bool) -> Utf8:
  match left inside:
    case _ False{}:
      Invalid{}
    case 1 True{}:
      Lead{}
    case _ True{}:
      Continuation{U32.sub(left, 1), 128, 191}

def utf8_scan(bytes: List<&2, U32>, state: Utf8) -> Bool:
  match bytes state:
    case Nil{} Lead{}:
      True{}
    case Nil{} _:
      False{}
    case _ Invalid{}:
      False{}
    case Con{+b, tail} Lead{}:
      utf8_scan(tail, utf8_lead(b, U32.is_le(b, 127),
        U32.is_ge(b, 194) && U32.is_le(b, 223),
        U32.is_ge(b, 224) && U32.is_le(b, 239),
        U32.is_ge(b, 240) && U32.is_le(b, 244)))
    case Con{+b, tail} Continuation{left, low, high}:
      utf8_scan(tail, utf8_next(left, U32.is_ge(b, low) && U32.is_le(b, high)))

def utf8_message(tag: U32, payload: List<&2, U32>, ok: Bool) -> Frame:
  match ok:
    case True{}:
      Message{tag, payload}
    case False{}:
      InvalidUtf8{}

def validated_message(+tag: U32, +payload: List<&2, U32>) -> Frame:
  match tag:
    case 11:
      utf8_message(tag, payload, utf8_scan(payload, Lead{}))
    case _:
      Message{tag, payload}

def validate(+tag: U32, payload: List<&2, U32>, +known: Bool, +fits: Bool, +permit: Bool, +length_ok: Bool) -> Frame:
  match known fits permit length_ok:
    case False{} _ _ _:
      UnknownTag{}
    case True{} False{} _ _:
      Oversized{}
    case True{} True{} False{} _:
      DisallowedTag{}
    case True{} True{} True{} False{}:
      InvalidLength{}
    case True{} True{} True{} True{}:
      validated_message(tag, payload)

def decode_header(+dir: Direction, +ver: Version, +full: U32, header: Header) -> Frame:
  match header:
    case Incomplete{}:
      TruncatedTag{}
    case Tag{+tag, width, payload}:
      +len = U32.sub(full, width)
      validate(tag, payload, U32.is_le(tag, 13), sender_limit(dir, full, len),
        allowed(dir, ver, tag), valid_length(tag, len))

def client_oversize(dir: Direction, size: U32) -> Bool:
  match dir:
    case ToRelay{}:
      U32.is_gt(size, 65536)
    case ToClient{}:
      False{}

def decode_with_size(dir: Direction, ver: Version, full: U32, bytes: List<&2, U32>, too_big: Bool) -> Frame:
  match too_big:
    case True{}:
      Oversized{}
    case False{}:
      decode_header(dir, ver, full, split_tag(bytes))

def decode_packet(+dir: Direction, ver: Version, bytes: List<&2, U32>, size: Size) -> Frame:
  match size:
    case NonByte{}:
      BadByte{}
    case TooLarge{}:
      Oversized{}
    case Length{+n}:
      decode_with_size(dir, ver, n, bytes, client_oversize(dir, n))

def decode(dir: Direction, ver: Version, +bytes: List<&2, U32>) -> Frame:
  decode_packet(dir, ver, bytes, measure(bytes, 0))

type Encoding is Data:
  Encoded{bytes: List<&2, U32>}
  Rejected{reason: Frame}

def emit(frame: Frame) -> Encoding:
  match frame:
    case Message{tag, payload}:
      Encoded{Con{tag, payload}}
    case _:
      Rejected{frame}

def encode_as(+dir: Direction, +ver: Version, +tag: U32, payload: List<&2, U32>, size: Size) -> Encoding:
  match size:
    case Length{+n}:
      emit(validate(tag, payload, U32.is_le(tag, 13), sender_limit(dir, U32.inc(n), n),
        allowed(dir, ver, tag), valid_length(tag, n)))
    case NonByte{}:
      Rejected{BadByte{}}
    case TooLarge{}:
      Rejected{Oversized{}}

def encode(dir: Direction, ver: Version, tag: U32, +payload: List<&2, U32>) -> Encoding:
  encode_as(dir, ver, tag, payload, measure(payload, 0))

# The peer is the destination for ToRelay and the sender for ToClient.
# ECN 0 carries no marking. A zero segment size means a single datagram.
type Packet is Data:
  Datagram{peer: List<&2, U32>, ecn: U32, segment: U32, contents: List<&2, U32>}
  PacketRejected{reason: Frame}

type Split is Data:
  Prefix{peer: List<&2, U32>, rest: List<&2, U32>}
  ShortPrefix{}

def split_peer(+left: Nat, bytes: List<&2, U32>, reversed: List<&2, U32>) -> Split:
  match left bytes:
    case 0n _:
      Prefix{List.reverse(&2, U32, reversed), bytes}
    case 1n+k Con{b, tail}:
      split_peer(k, tail, Con{b, reversed})
    case 1n+k Nil{}:
      ShortPrefix{}

def packet_fields(peer: List<&2, U32>, body: List<&2, U32>, batch: Bool) -> Packet:
  match body batch:
    case Con{ecn, Con{hi, Con{lo, rest}}} True{}:
      Datagram{peer, U32.and(ecn, 3), U32.or(U32.shln(hi, 8n), lo), rest}
    case Con{ecn, rest} False{}:
      Datagram{peer, U32.and(ecn, 3), 0, rest}
    case _ _:
      PacketRejected{InvalidLength{}}

def finish_packet(prefix: Split, batch: Bool) -> Packet:
  match prefix:
    case Prefix{peer, rest}:
      packet_fields(peer, rest, batch)
    case ShortPrefix{}:
      PacketRejected{InvalidLength{}}

def datagram_tag(+tag: U32, payload: List<&2, U32>) -> Packet:
  match tag:
    case 4:
      finish_packet(split_peer(32n, payload, []), False{})
    case 5:
      finish_packet(split_peer(32n, payload, []), True{})
    case 6:
      finish_packet(split_peer(32n, payload, []), False{})
    case 7:
      finish_packet(split_peer(32n, payload, []), True{})
    case _:
      PacketRejected{DisallowedTag{}}

def packet(frame: Frame) -> Packet:
  match frame:
    case Message{tag, payload}:
      datagram_tag(tag, payload)
    case _:
      PacketRejected{frame}

def decode_datagram(dir: Direction, ver: Version, bytes: List<&2, U32>) -> Packet:
  packet(decode(dir, ver, bytes))

def datagram_base_tag(dir: Direction) -> U32:
  match dir:
    case ToRelay{}:
      4
    case ToClient{}:
      6

def emit_datagram(+dir: Direction, ver: Version, peer: List<&2, U32>,
    ecn: U32, +segment: U32, contents: List<&2, U32>, single: Bool) -> Encoding:
  match single:
    case True{}:
      encode(dir, ver, datagram_base_tag(dir), List.append(&2, U32, peer, Con{ecn, contents}))
    case False{}:
      hi = U32.shrn(segment, 8n)
      lo = U32.and(segment, 255)
      encode(dir, ver, U32.inc(datagram_base_tag(dir)),
        List.append(&2, U32, peer, Con{ecn, Con{hi, Con{lo, contents}}}))

def datagram_checked(dir: Direction, ver: Version, peer: List<&2, U32>,
    +ecn: U32, +segment: U32, contents: List<&2, U32>, size: Size, metadata_ok: Bool) -> Encoding:
  match size metadata_ok:
    case NonByte{} _:
      Rejected{BadByte{}}
    case Length{32} True{}:
      emit_datagram(dir, ver, peer, ecn, segment, contents, U32.is_eq(segment, 0))
    case _ False{}:
      Rejected{BadByte{}}
    case _ True{}:
      Rejected{InvalidLength{}}

def encode_datagram(dir: Direction, ver: Version, +peer: List<&2, U32>,
    +ecn: U32, +segment: U32, contents: List<&2, U32>) -> Encoding:
  datagram_checked(dir, ver, peer, ecn, segment, contents, measure(peer, 0),
    U32.is_le(ecn, 3) && U32.is_le(segment, 65535))
