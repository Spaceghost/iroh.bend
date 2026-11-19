import Base
import ../src/relay.bend as Relay
import ../src/base32.bend as Base32

def bytes_equal(a: List<&2, U32>, b: List<&2, U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x, xs} Con{y, ys}:
      U32.is_eq(x, y) && bytes_equal(xs, ys)
    case _ _:
      False{}

def decoded(+tag: U32, payload: List<&2, U32>, actual: Relay.Frame) -> Bool:
  match actual:
    case Relay.Message{kind, data}:
      U32.is_eq(tag, kind) && bytes_equal(payload, data)
    case _:
      False{}

def encoded(expected: List<&2, U32>, actual: Relay.Encoding) -> Bool:
  match actual:
    case Relay.Encoded{bytes}:
      bytes_equal(expected, bytes)
    case _:
      False{}

def snapshot(+dir: Relay.Direction, +ver: Relay.Version, +tag: U32, +payload: List<&2, U32>) -> Bool:
  +wire = {Con{tag, payload} : List<&2,U32>}
  decoded(tag, payload, Relay.decode(dir, ver, wire)) &&
    encoded(wire, Relay.encode(dir, ver, tag, payload))

# Fixtures from iroh-relay's relay_client_frames and client_relay_frames
# snapshot tests, pinned to Iroh v1.5.0.
def snapshots() -> Bool:
  +peer = {[25,127,107,35,225,108,133,50,198,171,200,56,250,205,94,167,
      137,190,12,118,178,146,3,52,3,155,250,139,61,54,141,97] : List<&2,U32>}
  +ping = {[42,42,42,42,42,42,42,42] : List<&2,U32>}
  +single = List.append(&2, U32, peer, [3,72,101,108,108,111,32,87,111,114,108,100,33])
  +batch = List.append(&2, U32, peer, [3,0,6,72,101,108,108,111,32,87,111,114,108,100,33])
  snapshot(Relay.ToClient{}, Relay.V1{}, 11, [72,101,108,108,111,63,32,89,101,115,32,116,104,105,115,32,105,115,32,100,111,103,46]) &&
  snapshot(Relay.ToClient{}, Relay.V2{}, 8, peer) &&
  snapshot(Relay.ToClient{}, Relay.V2{}, 9, ping) &&
  snapshot(Relay.ToClient{}, Relay.V2{}, 10, ping) &&
  snapshot(Relay.ToClient{}, Relay.V2{}, 7, batch) &&
  snapshot(Relay.ToClient{}, Relay.V2{}, 6, single) &&
  snapshot(Relay.ToClient{}, Relay.V2{}, 12, [0,0,0,10,0,0,0,20]) &&
  snapshot(Relay.ToClient{}, Relay.V2{}, 13, [1]) &&
  snapshot(Relay.ToClient{}, Relay.V2{}, 13, [2]) &&
  snapshot(Relay.ToRelay{}, Relay.V2{}, 9, ping) &&
  snapshot(Relay.ToRelay{}, Relay.V2{}, 10, ping) &&
  snapshot(Relay.ToRelay{}, Relay.V2{}, 5, batch) &&
  snapshot(Relay.ToRelay{}, Relay.V2{}, 4, single)

def result_code(result: Relay.Frame) -> U32:
  match result:
    case Relay.Message{_, _}:
      0
    case Relay.BadByte{}:
      1
    case Relay.TruncatedTag{}:
      2
    case Relay.UnknownTag{}:
      3
    case Relay.DisallowedTag{}:
      4
    case Relay.InvalidLength{}:
      5
    case Relay.InvalidUtf8{}:
      6
    case Relay.Oversized{}:
      7

def result_is(d: Relay.Direction, v: Relay.Version, wire: List<&2, U32>, code: U32) -> Bool:
  U32.is_eq(result_code(Relay.decode(d, v, wire)), code)

def rejection_cases() -> Bool:
  +c = {Relay.ToClient{} : Relay.Direction}
  +r = {Relay.ToRelay{} : Relay.Direction}
  +v1 = {Relay.V1{} : Relay.Version}
  +v2 = {Relay.V2{} : Relay.Version}
  result_is(r, v2, [4], 5) &&
  result_is(r, v2, [5], 5) &&
  result_is(c, v2, [11], 4) &&
  result_is(c, v1, [13, 0], 4) &&
  result_is(r, v2, [8], 4) &&
  result_is(r, v2, [], 2) &&
  result_is(r, v2, [192,0,0,0,0,0,0], 2) &&
  result_is(r, v2, [192,0,0,0,1,0,0,9], 3) &&
  result_is(r, v2, [256], 1) &&
  result_is(r, v2, [64,9,0,0,0,0,0,0,0,0], 0) &&
  result_is(c, v2, [13,255,42], 0) &&
  result_is(c, v1, [11,194,162,226,130,172,240,159,152,128], 0) &&
  result_is(c, v1, [11,192,128], 6) &&
  result_is(c, v1, [11,224,159,128], 6) &&
  result_is(c, v1, [11,237,160,128], 6) &&
  result_is(c, v1, [11,244,144,128,128], 6) &&
  result_is(c, v1, [11,226,130], 6)

def pad(+n: Nat, acc: List<&2, U32>) -> List<&2, U32>:
  match n:
    case 0n:
      acc
    case 1n+k:
      pad(k, Con{0, acc})

def limits() -> Bool:
  +body = pad(65535n, [])
  +big = {Con{0, body} : List<&2,U32>}
  +bigger = {Con{0, big} : List<&2,U32>}
  +client = {Relay.ToClient{} : Relay.Direction}
  +relay = {Relay.ToRelay{} : Relay.Direction}
  +v2 = {Relay.V2{} : Relay.Version}
  result_is(relay, v2, Con{4,body}, 0) &&
  result_is(relay, v2, Con{5,body}, 0) &&
  result_is(relay, v2, Con{4,big}, 7) &&
  result_is(relay, v2, Con{5,big}, 7) &&
  result_is(client, v2, Con{6,big}, 0) &&
  result_is(client, v2, Con{6,bigger}, 7)

def packet_matches(expected: List<&2, U32>, +ecn: U32, +segment: U32,
    contents: List<&2, U32>, result: Relay.Packet) -> Bool:
  match result:
    case Relay.Datagram{peer, marking, size, rest}:
      bytes_equal(expected, peer) && U32.is_eq(ecn, marking) &&
        U32.is_eq(segment, size) && bytes_equal(contents, rest)
    case _:
      False{}

def datagram_cases() -> Bool:
  +peer = pad(32n, [])
  +data = {[0,255,42] : List<&2,U32>}
  +v2 = {Relay.V2{} : Relay.Version}
  +wire = List.append(&2, U32, [7], List.append(&2, U32, peer, [243,1,44,0,255,42]))
  +canonical = List.append(&2, U32, [7], List.append(&2, U32, peer, [3,1,44,0,255,42]))
  +zero_segment = List.append(&2, U32, [5], List.append(&2, U32, peer, [1,0,0,0,255,42]))
  +single = List.append(&2, U32, [4], List.append(&2, U32, peer, [1,0,255,42]))
  packet_matches(peer, 3, 300, data, Relay.decode_datagram(Relay.ToClient{}, v2, wire)) &&
  encoded(canonical, Relay.encode_datagram(Relay.ToClient{}, v2, peer, 3, 300, data)) &&
  packet_matches(peer, 1, 0, data, Relay.decode_datagram(Relay.ToRelay{}, v2, zero_segment)) &&
  encoded(single, Relay.encode_datagram(Relay.ToRelay{}, v2, peer, 1, 0, data))

def require(message: String, ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print(message)
    case False{}:
      IO.die(Unit, 1, String.append("FAIL ", message))

def main() -> IO(Unit):
  do IO<Unit>:
    require("PASS 13 upstream relay wire snapshots", snapshots())
    require("PASS 17 relay boundary and malformed-input cases", rejection_cases())
    require("PASS six relay frame-size boundary cases", limits())
    require("PASS relay datagrams and metadata", datagram_cases())
    require("PASS DNSSEC alphabet bounds", U32.is_eq(Base32.encode_half(0), 808464432) &&
      U32.is_eq(Base32.encode_half(1048575), 1987475062))
    return Unit{}
