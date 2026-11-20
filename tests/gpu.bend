import Base
import ../src/relay.bend as Relay
import ./punycode.bend as Punycode
import ./custom_addr.bend as Custom
import ./quic_close_wire.bend as CloseWire

def outcome(+expected: U32, decoded: Relay.Frame) -> U32:
  match decoded:
    case Relay.Message{9, Con{value, _}}:
      Bool.to_u32(U32.is_eq(value, expected))
    case _:
      0

def one(+i: U32) -> U32:
  +byte = U32.and(U32.shrn(i, 3n), 255)
  outcome(byte, Relay.decode(Relay.ToRelay{}, Relay.V2{}, [9,byte,0,1,2,3,4,5,255]))

def batch(+d: Nat, +start: U32, +width: U32) -> U32:
  match d:
    case 0n:
      one(start)
    case 1n+k:
      +half = U32.shrn(width, 1n)
      a b = batch(k, start, half) batch(k, U32.add(start, half), half)
      U32.add(a, b)

def idna_pair(i: U32) -> U32:
  match i:
    case 0:
      Bool.to_u32(Punycode.pair("他们为什么不说中文","ihqwcrb4cv8a8dqg056pqjye"))
    case 1:
      Bool.to_u32(Punycode.pair("mañana","maana-pta"))
    case 2:
      Bool.to_u32(Punycode.pair("हिन्दी","j2bd4cyah0f"))
    case _:
      Bool.to_u32(Punycode.pair("☃-⌘","--dqo34k"))

def custom_address(i: U32) -> U32:
  match i:
    case 0:
      Bool.to_u32(String.eq(Custom.one("0_"),"0_ 0000000000000000"))
    case 1:
      Bool.to_u32(String.eq(Custom.one("+123456789ABCDEF0_00ff"),"123456789abcdef0_00ff f0debc9a7856341200ff"))
    case 2:
      Bool.to_u32(String.eq(Custom.binary([255,255,255,255,255,255,255,255,0,255]),"ffffffffffffffff_00ff"))
    case _:
      Bool.to_u32(String.eq(Custom.one("10000000000000000_"),"invalid id"))

def vector_pairs(~sample: U32 -> U32, +depth: Nat, +i: U32) -> U32:
  match depth:
    case 0n:
      sample(i)
    case 1n+rest:
      +base = U32.mul(i,2)
      left right = vector_pairs(~sample,rest,base) vector_pairs(~sample,rest,U32.inc(base))
      U32.add(left,right)

def require(success: Bool) -> IO(Unit):
  match success:
    case True{}:
      IO.print("PASS 16384 relay ping decodes, 4 Punycode vectors, 4 custom addresses, and 8 connection close vectors on CUDA")
    case False{}:
      IO.die(Unit, 1, "CUDA conformance vector mismatch")

def main() -> IO(Unit):
  +passed = batch!(14n, 0, 16384)
  +labels = vector_pairs!(i => idna_pair(i),2n,0)
  +addresses = vector_pairs!(i => custom_address(i),2n,0)
  +closes = CloseWire.count!(3n,0)
  require(U32.is_eq(passed,16384) && U32.is_eq(labels,4) && U32.is_eq(addresses,4) && U32.is_eq(closes,8))
