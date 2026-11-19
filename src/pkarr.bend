import Base
import ./discovery.bend as Dns
import ./relay.bend as Bytes
import ./ed25519.bend as Ed

type Signed is Data:
  Envelope{key: List<&2,U32>, signature: List<&2,U32>, timestamp: List<&2,U32>, dns: List<&2,U32>}
  BadEnvelope{}

def time_size(key: List<&2,U32>, signature: List<&2,U32>, item: Bytes.Split) -> Signed:
  match item:
    case Bytes.Prefix{timestamp,dns}:
      Envelope{key,signature,timestamp,dns}
    case Bytes.ShortPrefix{}:
      BadEnvelope{}

def signature_size(key: List<&2,U32>, sig: Bytes.Split) -> Signed:
  match sig:
    case Bytes.Prefix{signature,tail}:
      time_size(key,signature,Bytes.split_peer(8n,tail,[]))
    case Bytes.ShortPrefix{}:
      BadEnvelope{}

def key_size(parts: Bytes.Split) -> Signed:
  match parts:
    case Bytes.Prefix{key,tail}:
      signature_size(key,Bytes.split_peer(64n,tail,[]))
    case Bytes.ShortPrefix{}:
      BadEnvelope{}

def parse_sized(wire: List<&2,U32>, size: Bytes.Size) -> Signed:
  match size:
    case Bytes.Length{_}:
      key_size(Bytes.split_peer(32n,wire,[]))
    case _:
      BadEnvelope{}

def parse(+wire: List<&2,U32>) -> Signed:
  parse_sized(wire,Bytes.measure_limited(wire,1104))

# Decimal digits are kept least significant first. Each step multiplies by
# 256 and adds one big-endian timestamp byte. This represents all u64 values
# without relying on native integer width.
def final_carry(+fuel: Nat, +carry: U32, nonzero: Bool) -> List<&2,U32>:
  match fuel nonzero:
    case 1n+k True{}:
      +rest = U32.div(carry,10)
      Con{U32.mod(carry,10),final_carry(k,rest,U32.is_gt(rest,0))}
    case _ _:
      []

def decimal_step(digits: List<&2,U32>, +carry: U32) -> List<&2,U32>:
  match digits:
    case Nil{}:
      final_carry(3n,carry,U32.is_gt(carry,0))
    case Con{d,tail}:
      +next = U32.add(U32.mul(d,256),carry)
      Con{U32.mod(next,10),decimal_step(tail,U32.div(next,10))}

def decimal(bytes: List<&2,U32>, digits: List<&2,U32>) -> List<&2,U32>:
  match bytes:
    case Nil{}:
      List.reverse(&2,U32,digits)
    case Con{byte,tail}:
      decimal(tail,decimal_step(digits,byte))

def ascii(digits: List<&2,U32>) -> List<&2,U32>:
  match digits:
    case Nil{}:
      []
    case Con{d,tail}:
      Con{U32.add(48,d),ascii(tail)}

def transcript(timestamp: List<&2,U32>, +dns: List<&2,U32>) -> List<&2,U32>:
  size = U32.from_nat(List.length(&2,U32,dns))
  List.append(&2,U32,Dns.keyword("3:seqi"),List.append(&2,U32,ascii(decimal(timestamp,[0])),
    List.append(&2,U32,Dns.keyword("e1:v"),List.append(&2,U32,Dns.keyword(U32.show(size)),Con{58,dns}))))

type Verification is Data:
  Verified{timestamp: List<&2,U32>, records: List<&2,Dns.Attribute>}
  BadPacket{}
  WrongKey{}
  InvalidSignature{}

def decoded(timestamp: List<&2,U32>, answer: Dns.Reply) -> Verification:
  match answer:
    case Dns.Found{records}:
      Verified{timestamp,records}
    case _:
      BadPacket{}

def checked(key: List<&2,U32>, timestamp: List<&2,U32>, dns: List<&2,U32>, valid: Bool) -> Verification:
  match valid:
    case True{}:
      decoded(timestamp,Dns.signed_records(key,dns))
    case False{}:
      InvalidSignature{}

def verify_envelope(+key: List<&2,U32>, signature: List<&2,U32>, +timestamp: List<&2,U32>,
    +dns: List<&2,U32>, matches: Bool) -> IO(Verification):
  match matches:
    case False{}:
      IO.pure(Verification,WrongKey{})
    case True{}:
      do IO<Verification>:
        ok : Bool <- Ed.verify(key,signature,transcript(timestamp,dns))
        return checked(key,timestamp,dns,ok)

def verify_packet(expected_key: List<&2,U32>, envelope: Signed) -> IO(Verification):
  match envelope:
    case Envelope{+key,signature,timestamp,dns}:
      verify_envelope(key,signature,timestamp,dns,Dns.bytes_eq(expected_key,key))
    case BadEnvelope{}:
      IO.pure(Verification,BadPacket{})

def verify(expected_key: List<&2,U32>, wire: List<&2,U32>) -> IO(Verification):
  verify_packet(expected_key,parse(wire))

# The relay URL already contains the expected key, so its HTTP body starts
# with the signature. Verification still binds the packet to that key.
def verify_relay_body(+expected_key: List<&2,U32>, body: List<&2,U32>) -> IO(Verification):
  verify(expected_key,List.append(&2,U32,expected_key,body))

def packed(key: List<&2,U32>, signature: List<&2,U32>, timestamp: List<&2,U32>, dns: List<&2,U32>,
    valid: Bool) -> Result<&1,&1,U32 & String,List<&2,U32>>:
  match valid:
    case True{}:
      Done{List.append(&2,U32,key,List.append(&2,U32,signature,List.append(&2,U32,timestamp,dns)))}
    case False{}:
      Fail{(1,"Pkarr signing key does not match the endpoint")}

def signed_result(result: Result<&1,&1,U32 & String,List<&2,U32> & List<&2,U32>>,
    expected: List<&2,U32>, timestamp: List<&2,U32>, dns: List<&2,U32>)
    -> Result<&1,&1,U32 & String,List<&2,U32>>:
  match result:
    case Done{(+key,signature)}:
      packed(key,signature,timestamp,dns,Dns.bytes_eq(expected,key))
    case Fail{error}:
      Fail{error}

def sign_dns(seed: List<&2,U32>, key: List<&2,U32>, +timestamp: List<&2,U32>,
    packet: Maybe<&2,List<&2,U32>>, size: Bytes.Size)
    -> IO(Result<&1,&1,U32 & String,List<&2,U32>>):
  match packet size:
    case Some{+dns} Bytes.Length{8}:
      do IO<Result<&1,&1,U32 & String,List<&2,U32>>>:
        result : Result<&1,&1,U32 & String,List<&2,U32> & List<&2,U32>> <- Ed.sign(seed,transcript(timestamp,dns))
        return signed_result(result,key,timestamp,dns)
    case _ _:
      IO.pure(Result<&1,&1,U32 & String,List<&2,U32>>,Fail{(1,"invalid Pkarr timestamp or TXT packet")})

def sign(seed: List<&2,U32>, +key: List<&2,U32>, +timestamp: List<&2,U32>,
    records: List<&2,Dns.Attribute>, ttl: U32) -> IO(Result<&1,&1,U32 & String,List<&2,U32>>):
  sign_dns(seed,key,timestamp,Dns.signed_dns(key,records,ttl),Bytes.measure_limited(timestamp,8))
