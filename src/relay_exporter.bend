import Base
import ./relay.bend as Wire
import ./ed25519.bend as Ed

type Proof is Data:
  ExporterProof{key: List<&2,U32>, signature: List<&2,U32>, suffix: List<&2,U32>}
  MalformedExporterProof{}

def digit_range(+c: U32, upper: Bool, lower: Bool, number: Bool) -> U32:
  match upper lower number:
    case True{} _ _:
      U32.sub(c,65)
    case _ True{} _:
      U32.sub(c,71)
    case _ _ True{}:
      U32.add(c,4)
    case _ _ _:
      64

def digit(+c: U32) -> U32:
  match c:
    case 45:
      62
    case 95:
      63
    case _:
      digit_range(c,U32.is_ge(c,65) && U32.is_le(c,90),
        U32.is_ge(c,97) && U32.is_le(c,122),U32.is_ge(c,48) && U32.is_le(c,57))

def b0(a: U32,b: U32) -> U32:
  U32.or(U32.shln(a,2n),U32.shrn(b,4n))

def b1(b: U32,c: U32) -> U32:
  U32.or(U32.shln(U32.and(b,15),4n),U32.shrn(c,2n))

def group(a: U32,+b: U32,+c: U32,d: U32, rest: Maybe<&2,List<&2,U32>>,
    valid: Bool) -> Maybe<&2,List<&2,U32>>:
  match rest valid:
    case Some{tail} True{}:
      Some{Con{b0(a,b),Con{b1(b,c),Con{U32.or(U32.shln(U32.and(c,3),6n),d),tail}}}}
    case _ _:
      None{}

def tail_bytes(a: U32,+b: U32,c: U32, valid: Bool) -> Maybe<&2,List<&2,U32>>:
  match valid:
    case True{}:
      Some{[b0(a,b),b1(b,c)]}
    case False{}:
      None{}

def decode_groups(bytes: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  match bytes:
    case Con{a,Con{b,Con{c,Con{d,rest}}}}:
      +x = digit(a)
      +y = digit(b)
      +z = digit(c)
      +w = digit(d)
      group(x,y,z,w,decode_groups(rest),
        U32.is_lt(x,64) && U32.is_lt(y,64) && U32.is_lt(z,64) && U32.is_lt(w,64))
    case [a,b,c]:
      +x = digit(a)
      +y = digit(b)
      +z = digit(c)
      tail_bytes(x,y,z,
        U32.is_lt(x,64) && U32.is_lt(y,64) && U32.is_lt(z,64) && U32.is_eq(U32.and(z,3),0))
    case _:
      None{}

def proof_suffix(key: List<&2,U32>, split: Wire.Split) -> Proof:
  match split:
    case Wire.Prefix{signature,suffix}:
      ExporterProof{key,signature,suffix}
    case Wire.ShortPrefix{}:
      MalformedExporterProof{}

def proof_sig(key: List<&2,U32>, remaining: List<&2,U32>) -> Proof:
  match remaining:
    case Con{64,tail}:
      proof_suffix(key,Wire.split_peer(64n,tail,[]))
    case _:
      MalformedExporterProof{}

def proof_key(split: Wire.Split) -> Proof:
  match split:
    case Wire.Prefix{key,remaining}:
      proof_sig(key,remaining)
    case _:
      MalformedExporterProof{}

def from_decoded(value: Maybe<&2,List<&2,U32>>) -> Proof:
  match value:
    case Some{bytes}:
      proof_key(Wire.split_peer(32n,bytes,[]))
    case None{}:
      MalformedExporterProof{}

def decode_sized(header: List<&2,U32>, size: Wire.Size) -> Proof:
  match size:
    case Wire.Length{151}:
      from_decoded(decode_groups(header))
    case _:
      MalformedExporterProof{}

# Postcard's 113-byte public-key, signature and exporter-suffix structure
# encodes to exactly 151 bytes of unpadded base64url.
def decode(+header: List<&2,U32>) -> Proof:
  decode_sized(header,Wire.measure_limited(header,151))

def same_bytes(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(x,y) && same_bytes(xs,ys)
    case _ _:
      False{}

def verified(matching: Bool, key: List<&2,U32>, signature: List<&2,U32>,
    message: List<&2,U32>) -> IO(Bool):
  match matching:
    case True{}:
      Ed.verify(key,signature,message)
    case False{}:
      IO.pure(Bool,False{})

def verify_split(parts: Wire.Split, key: List<&2,U32>, signature: List<&2,U32>,
    suffix: List<&2,U32>) -> IO(Bool):
  match parts:
    case Wire.Prefix{message,check}:
      verified(same_bytes(suffix,check),key,signature,message)
    case _:
      IO.pure(Bool,False{})

def verify(key: List<&2,U32>, signature: List<&2,U32>, suffix: List<&2,U32>,
    material: List<&2,U32>) -> IO(Bool):
  verify_split(Wire.split_peer(16n,material,[]),key,signature,suffix)
