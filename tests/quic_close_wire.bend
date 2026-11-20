import Base
import ../src/quic_nat.bend as Wire
import ../src/quic_close_wire.bend as CloseWire
import ../src/quic_close.bend as Close

def empty(result: Maybe<&2,CloseWire.Application>) -> Bool:
  match result:
    case None{}:
      True{}
    case _:
      False{}

def binary(result: Maybe<&2,CloseWire.Application>) -> Bool:
  match result:
    case Some{CloseWire.Received{Wire.Var{1073741823,4294967295},Con{0,Con{255,Con{29,Nil{}}}}}}:
      True{}
    case _:
      False{}

def closing() -> List<&2,U32>:
  Con{29,Wire.integer_bytes(1073741823,4294967295,[3,0,255,29,0])}

def native_snapshot(id: U32) -> Close.NativeResult():
  match id:
    case 4:
      Fail{(110,"idle timeout")}
    case 5:
      Fail{(9,"closed handle")}
    case 6:
      Done{Some{None{}}}
    case _:
      # A peer can independently use 110 as an application close code.
      Done{Some{Some{((0,110),[0,255])}}}

def matches_close(id: U32, result: Close.ReadResult()) -> Bool:
  match id result:
    case 4 Done{Some{Close.TimedOut{}}}:
      True{}
    case 5 Fail{(9,"closed handle")}:
      True{}
    case 6 Done{Some{Close.LocallyClosed{}}}:
      True{}
    case 7 Done{Some{Close.ApplicationClosed{Wire.Var{0,110},[0,255]}}}:
      True{}
    case _ _:
      False{}

def vector(id: U32) -> Bool:
  match id:
    case 0:
      # ACK_ECN with a second range, then a STREAM with offset, length, FIN and binary data.
      binary(CloseWire.application(List.append(&2,U32,[3,12,0,1,0,1,0,0,0,0,15,0,1,3,29,0,0],closing())))
    case 1:
      # NEW_CONNECTION_ID, a path challenge, a length-bearing DATAGRAM, and a close.
      prefix : List<&2,U32> = [24,0,0,2,1,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,26,1,2,3,4,5,6,7,8,49,3,29,0,0]
      binary(CloseWire.application(List.append(&2,U32,prefix,closing())))
    case 2:
      empty(CloseWire.application(Con{48,closing()}))
    case 3:
      binary(CloseWire.application(List.append(&2,U32,[29,0,0,0,1,28,0,0,2,42,0],closing())))
    case +n:
      matches_close(n,Close.decode(native_snapshot(n)))

def count(+depth: Nat, +index: U32) -> U32:
  match depth:
    case 0n:
      Bool.to_u32(vector(index))
    case 1n+left:
      +next = U32.mul(index,2)
      a b = count(left,next) count(left,U32.inc(next))
      U32.add(a,b)

def check(passed: Bool) -> IO(Unit):
  match passed:
    case True{}:
      IO.print("PASS application close frame boundaries and public connection close reasons")
    case False{}:
      IO.die(Unit,1,"connection close vector mismatch")

def main() -> IO(Unit):
  check(U32.is_eq(count(3n,0),8))
