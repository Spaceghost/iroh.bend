import Base
import ../src/relay.bend as Relay

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

def require(success: Bool) -> IO(Unit):
  match success:
    case True{}:
      IO.print("PASS 16384 relay ping decodes on CUDA")
    case False{}:
      IO.die(Unit, 1, "CUDA relay ping decode mismatch")

def main() -> IO(Unit):
  +passed = batch!(14n, 0, 16384)
  require(U32.is_eq(passed, 16384))
