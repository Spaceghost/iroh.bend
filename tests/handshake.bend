import Base
import ../src/handshake.bend as Handshake
import ../src/relay_challenge.bend as Digest

def equal(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(x,y) && equal(xs,ys)
    case _ _:
      False{}

def matches(expected: Handshake.Auth, actual: Handshake.Auth) -> Bool:
  match expected actual:
    case Handshake.Challenge{a} Handshake.Challenge{b}:
      equal(a,b)
    case Handshake.ClientProof{pk,sig} Handshake.ClientProof{pk2,sig2}:
      equal(pk,pk2) && equal(sig,sig2)
    case Handshake.Confirmed{} Handshake.Confirmed{}:
      True{}
    case Handshake.Denied{a} Handshake.Denied{b}:
      equal(a,b)
    case Handshake.InvalidAuth{} Handshake.InvalidAuth{}:
      True{}
    case _ _:
      False{}

def encoded(wire: List<&2,U32>, result: Handshake.Encoding) -> Bool:
  match result:
    case Handshake.Encoded{got}:
      equal(wire,got)
    case Handshake.InvalidEncoding{}:
      False{}

def codec_case(+wire: List<&2,U32>, +frame: Handshake.Auth) -> Bool:
  matches(frame, Handshake.decode(wire)) && encoded(wire, Handshake.encode(frame))

def relay_frames() -> Bool:
  +nonce = {[0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15] : List<&2,U32>}
  +key = {[25,127,107,35,225,108,133,50,198,171,200,56,250,205,94,167,
      137,190,12,118,178,146,3,52,3,155,250,139,61,54,141,97] : List<&2,U32>}
  +sig = List.replicate(U32, 64n, 255)
  +reason = List.replicate(U32, 130n, 97)
  codec_case(Con{0,nonce}, Handshake.Challenge{nonce}) &&
    codec_case(Con{1,List.append(&2, U32, key, Con{64,sig})}, Handshake.ClientProof{key,sig}) &&
    codec_case([2], Handshake.Confirmed{}) &&
    codec_case([3,2,195,169], Handshake.Denied{[195,169]}) &&
    codec_case(Con{3,Con{130,Con{1,reason}}}, Handshake.Denied{reason}) &&
    matches(Handshake.Confirmed{}, Handshake.decode([64,2])) &&
    matches(Handshake.InvalidAuth{}, Handshake.decode([0,1,2])) &&
    matches(Handshake.InvalidAuth{}, Handshake.decode([3,2,195])) &&
    matches(Handshake.InvalidAuth{}, Handshake.decode([3,2,195,65])) &&
    matches(Handshake.InvalidAuth{}, Handshake.decode([3,128,128,128,128,128,128,128,128,128,128,0])) &&
    matches(Handshake.InvalidAuth{}, Handshake.decode([4,0]))

# Expected digests from blake3::derive_key using the Iroh 1.5.0 domain.
def challenge_vectors() -> Bool:
  equal(Digest.derive(List.replicate(U32, 16n, 0)),
      [129,5,231,189,153,99,25,78,109,109,128,34,90,63,27,7,
       29,163,182,230,94,220,209,37,49,225,98,51,243,61,233,214]) &&
  equal(Digest.derive([0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]),
      [183,177,110,80,93,44,181,219,175,73,72,0,9,44,59,5,
       166,196,93,141,63,212,241,184,136,198,167,114,64,184,118,192]) &&
  equal(Digest.derive(List.replicate(U32, 16n, 255)),
      [74,125,28,222,226,26,213,144,57,3,227,155,234,150,59,202,
       86,22,22,153,123,31,164,72,194,86,209,205,210,68,182,228]) &&
  equal(Digest.derive(List.replicate(U32, 16n, 256)), [])

def require(message: String, ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print(String.append("PASS ",message))
    case False{}:
      IO.die(Unit,1,String.append("FAIL ",message))

def main() -> IO(Unit):
  do IO<Unit>:
    require("relay challenge handshake wire encoding", relay_frames())
    require("Iroh relay BLAKE3 challenge derivation", challenge_vectors())
