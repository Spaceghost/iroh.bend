import Base
import ./relay.bend as Wire

# The binary messages exchanged after upgrading to the relay WebSocket.
# This codec exposes key and signature bytes for cryptographic verification.
type Auth is Data:
  Challenge{nonce: List<&2,U32>}
  ClientProof{key: List<&2,U32>, signature: List<&2,U32>}
  Confirmed{}
  Denied{reason: List<&2,U32>}
  InvalidAuth{}

type Length is Data:
  LValue{n: U32, rest: List<&2,U32>}
  BadLength{}

# Postcard unsigned integer encoding is little-endian base 128. A u64 has
# at most ten bytes, and these messages fit the relay WebSocket frame limit.
# Track high groups separately to reject overflow, even in overlong input.
def add_group(+group: U32, +shift: U32, +value: U32) -> U32:
  U32.add(value, U32.shln(group, U32.to_nat(shift)))

def group_value(group: U32, shift: U32, value: U32, +high: Bool) -> U32:
  match high:
    case True{}:
      U32.max(value, U32.mul(Bool.to_u32(U32.is_gt(group, 0)), 1048577))
    case False{}:
      add_group(group, shift, value)

def postcard_length(+fuel: Nat, bytes: List<&2,U32>, +shift: U32, +value: U32, +done: Bool) -> Length:
  match fuel bytes done:
    case _ _ True{}:
      LValue{value, bytes}
    case 1n+k Con{+byte, tail} False{}:
      postcard_length(k, tail, U32.add(shift, 7),
        group_value(U32.and(byte, 127), shift, value, U32.is_ge(shift, 21)),
        U32.is_le(byte, 127))
    case _ _ False{}:
      BadLength{}

def challenge(prefix: Wire.Split) -> Auth:
  match prefix:
    case Wire.Prefix{nonce, _}:
      Challenge{nonce}
    case Wire.ShortPrefix{}:
      InvalidAuth{}

def signature(key: List<&2,U32>, split: Wire.Split) -> Auth:
  match split:
    case Wire.Prefix{sig, _}:
      ClientProof{key, sig}
    case Wire.ShortPrefix{}:
      InvalidAuth{}

def proof_body(key: List<&2,U32>, length: Length) -> Auth:
  match length:
    case LValue{64, rest}:
      signature(key, Wire.split_peer(64n, rest, []))
    case _:
      InvalidAuth{}

def proof(prefix: Wire.Split) -> Auth:
  match prefix:
    case Wire.Prefix{key, body}:
      proof_body(key, postcard_length(10n, body, 0, 0, False{}))
    case Wire.ShortPrefix{}:
      InvalidAuth{}

def denial_utf8(reason: List<&2,U32>, valid: Bool) -> Auth:
  match valid:
    case True{}:
      Denied{reason}
    case False{}:
      InvalidAuth{}

def denial_prefix(prefix: Wire.Split) -> Auth:
  match prefix:
    case Wire.Prefix{+reason, _}:
      denial_utf8(reason, Wire.utf8_scan(reason, Wire.Lead{}))
    case Wire.ShortPrefix{}:
      InvalidAuth{}

def denial_size(+len: U32, bytes: List<&2,U32>, fits: Bool) -> Auth:
  match fits:
    case True{}:
      denial_prefix(Wire.split_peer(U32.to_nat(len), bytes, []))
    case False{}:
      InvalidAuth{}

def denial(length: Length) -> Auth:
  match length:
    case LValue{+n, rest}:
      denial_size(n, rest, U32.is_le(n, 1048576))
    case BadLength{}:
      InvalidAuth{}

def decode_body(+tag: U32, bytes: List<&2,U32>) -> Auth:
  match tag:
    case 0:
      challenge(Wire.split_peer(16n, bytes, []))
    case 1:
      proof(Wire.split_peer(32n, bytes, []))
    case 2:
      Confirmed{}
    case 3:
      denial(postcard_length(10n, bytes, 0, 0, False{}))
    case _:
      InvalidAuth{}

def decode_header(header: Wire.Header) -> Auth:
  match header:
    case Wire.Tag{tag, _, bytes}:
      decode_body(tag, bytes)
    case Wire.Incomplete{}:
      InvalidAuth{}

def decode_checked(bytes: List<&2,U32>, size: Wire.Size) -> Auth:
  match size:
    case Wire.Length{_}:
      decode_header(Wire.split_tag(bytes))
    case _:
      InvalidAuth{}

def decode(+bytes: List<&2,U32>) -> Auth:
  decode_checked(bytes, Wire.measure_limited(bytes, 1048576))

type ReasonChar is Data:
  EmitChar{value: U32}
  ContinueChar{left: U32, value: U32}

def wide_char(byte: U32, four: Bool) -> ReasonChar:
  match four:
    case True{}:
      ContinueChar{3,U32.and(byte,7)}
    case False{}:
      ContinueChar{2,U32.and(byte,15)}

def leading_char(+byte: U32, prefix: U32) -> ReasonChar:
  match prefix:
    case 6:
      ContinueChar{1,U32.and(byte,31)}
    case 7:
      wide_char(byte,U32.is_ge(byte,240))
    case _:
      EmitChar{byte}

def next_char(+value: U32, left: U32) -> ReasonChar:
  match left:
    case 1:
      EmitChar{value}
    case _:
      ContinueChar{U32.sub(left,1),value}

def reason_byte(byte: U32, state: ReasonChar) -> ReasonChar:
  match state:
    case EmitChar{_}:
      +lead = byte
      leading_char(lead,U32.shrn(lead,5n))
    case ContinueChar{left,value}:
      next_char(U32.or(U32.shln(value,6n),U32.and(byte,63)),left)

def collect_char(state: ReasonChar, rest: List<&2,Char>) -> List<&2,Char>:
  match state:
    case EmitChar{point}:
      Con{Char.from_u32(point),rest}
    case _:
      rest

def reason_chars(bytes: List<&2,U32>, state: ReasonChar) -> List<&2,Char>:
  match bytes:
    case Nil{}:
      []
    case Con{byte,tail}:
      +next = reason_byte(byte,state)
      collect_char(next,reason_chars(tail,next))

# Denied frames have already passed UTF-8 validation in decode.
def reason_text(bytes: List<&2,U32>) -> String:
  String.from_list(reason_chars(bytes,EmitChar{0}))

type Encoding is Data:
  Encoded{bytes: List<&2,U32>}
  InvalidEncoding{}

def fixed_size(bytes: List<&2,U32>, tag: U32, ok: Bool) -> Encoding:
  match ok:
    case True{}:
      Encoded{Con{tag, bytes}}
    case False{}:
      InvalidEncoding{}

def fixed(bytes: List<&2,U32>, tag: U32, actual: Wire.Size, +expected: U32) -> Encoding:
  match actual:
    case Wire.Length{n}:
      fixed_size(bytes, tag, U32.is_eq(n, expected))
    case _:
      InvalidEncoding{}

def encode_proof(+key: List<&2,U32>, +sig: List<&2,U32>, key_size: Wire.Size, sig_size: Wire.Size) -> Encoding:
  match key_size sig_size:
    case Wire.Length{32} Wire.Length{64}:
      Encoded{Con{1, List.append(&2, U32, key, Con{64, sig})}}
    case _ _:
      InvalidEncoding{}

def postcard_put(+left: Nat, +size: U32, remainder: List<&2,U32>, +more: Bool) -> List<&2,U32>:
  match left more:
    case 1n+k True{}:
      +next = U32.shrn(size, 7n)
      Con{U32.or(U32.and(size, 127), 128),
        postcard_put(k, next, remainder, U32.is_ge(next, 128))}
    case _ _:
      Con{size, remainder}

def encode_denial(+reason: List<&2,U32>, size: Wire.Size, utf8: Bool) -> Encoding:
  match size utf8:
    case Wire.Length{+n} True{}:
      Encoded{Con{3, postcard_put(2n, n, reason, U32.is_ge(n, 128))}}
    case _ _:
      InvalidEncoding{}

def encode(frame: Auth) -> Encoding:
  match frame:
    case Challenge{+nonce}:
      fixed(nonce, 0, Wire.measure_limited(nonce, 16), 16)
    case ClientProof{+key, +sig}:
      encode_proof(key, sig, Wire.measure_limited(key, 32), Wire.measure_limited(sig, 64))
    case Confirmed{}:
      Encoded{[2]}
    case Denied{+reason}:
      encode_denial(reason, Wire.measure_limited(reason, 1048572), Wire.utf8_scan(reason, Wire.Lead{}))
    case InvalidAuth{}:
      InvalidEncoding{}
