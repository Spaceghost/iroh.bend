import Base
import ../src/relay.bend as Relay
import ./punycode.bend as Punycode

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

def idna_pairs(+depth: Nat, +i: U32) -> U32:
  match depth:
    case 0n:
      idna_pair(i)
    case 1n+rest:
      +base = U32.mul(i,2)
      left right = idna_pairs(rest,base) idna_pairs(rest,U32.inc(base))
      U32.add(left,right)

def require(success: Bool) -> IO(Unit):
  match success:
    case True{}:
      IO.print("PASS 16384 relay ping decodes and 4 Punycode encode/decode vectors on CUDA")
    case False{}:
      IO.die(Unit, 1, "CUDA conformance vector mismatch")

def main() -> IO(Unit):
  +passed = batch!(14n, 0, 16384)
  +labels = idna_pairs!(2n,0)
  require(U32.is_eq(passed,16384) && U32.is_eq(labels,4))
