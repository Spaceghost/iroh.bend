import Base
import ../src/quic_nat.bend as NatWire

def bytes_equal(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(x,y) && bytes_equal(xs,ys)
    case _ _:
      False{}

def encoded(expected: List<&2,U32>, actual: Maybe<&2,List<&2,U32>>) -> Bool:
  match actual:
    case Some{bytes}:
      bytes_equal(expected,bytes)
    case None{}:
      False{}

def same_address(a: NatWire.Address, b: NatWire.Address) -> Bool:
  match a b:
    case NatWire.IPv4{x} NatWire.IPv4{y}:
      bytes_equal(x,y)
    case NatWire.IPv6{x} NatWire.IPv6{y}:
      bytes_equal(x,y)
    case _ _:
      False{}

def same_integer(a: NatWire.VarInt, b: NatWire.VarInt) -> Bool:
  NatWire.Var{hi,lo} = a
  NatWire.Var{other_hi,other_lo} = b
  U32.is_eq(hi,other_hi) && U32.is_eq(lo,other_lo)

def same_frame(a: NatWire.Frame, b: NatWire.Frame) -> Bool:
  match a b:
    case NatWire.AddAddress{seq,ip,port} NatWire.AddAddress{other_seq,other_ip,other_port}:
      same_integer(seq,other_seq) && same_address(ip,other_ip) && U32.is_eq(port,other_port)
    case NatWire.ReachOut{round,ip,port} NatWire.ReachOut{other_round,other_ip,other_port}:
      same_integer(round,other_round) && same_address(ip,other_ip) && U32.is_eq(port,other_port)
    case NatWire.RemoveAddress{seq} NatWire.RemoveAddress{other_seq}:
      same_integer(seq,other_seq)
    case _ _:
      False{}

def decoded(expected: NatWire.Frame, rest: List<&2,U32>, result: NatWire.DecodeResult) -> Bool:
  match result:
    case NatWire.Decoded{frame,tail}:
      same_frame(expected,frame) && bytes_equal(rest,tail)
    case _:
      False{}

def exact(+frame: NatWire.Frame, +wire: List<&2,U32>) -> Bool:
  encoded(wire,NatWire.encode(frame)) &&
    decoded(frame,[1,0],NatWire.decode(List.append(&2,U32,wire,[1,0])))

# The IPv4 ADD_ADDRESS, IPv6 REACH_OUT, and REMOVE_ADDRESS values match
# the noq-proto 1.5.0 roundtrip tests. Cover both address families for both tags.
def frame_vectors() -> Bool:
  +v4 = {NatWire.IPv4{[127,0,0,1]} : NatWire.Address}
  +v6 = {NatWire.IPv6{[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]} : NatWire.Address}
  +seq = {NatWire.Var{0,42} : NatWire.VarInt}
  exact(NatWire.AddAddress{seq,v4,4242},[128,61,127,144,42,127,0,0,1,16,146]) &&
  exact(NatWire.AddAddress{seq,v6,4242},[128,61,127,145,42,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,16,146]) &&
  exact(NatWire.ReachOut{seq,v4,4242},[128,61,127,146,42,127,0,0,1,16,146]) &&
  exact(NatWire.ReachOut{seq,v6,4242},[128,61,127,147,42,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,16,146]) &&
  exact(NatWire.RemoveAddress{NatWire.Var{0,10}},[128,61,127,148,10])

def sequence_vector(hi: U32, lo: U32, sequence: List<&2,U32>) -> Bool:
  exact(NatWire.RemoveAddress{NatWire.Var{hi,lo}},Con{128,Con{61,Con{127,Con{148,sequence}}}})

def sequence_vectors() -> Bool:
  sequence_vector(0,0,[0]) &&
  sequence_vector(0,63,[63]) &&
  sequence_vector(0,64,[64,64]) &&
  sequence_vector(0,16383,[127,255]) &&
  sequence_vector(0,16384,[128,0,64,0]) &&
  sequence_vector(0,1073741823,[191,255,255,255]) &&
  sequence_vector(0,1073741824,[192,0,0,0,64,0,0,0]) &&
  sequence_vector(1,305419896,[192,0,0,1,18,52,86,120]) &&
  sequence_vector(1073741823,4294967295,[255,255,255,255,255,255,255,255]) &&
  decoded(NatWire.RemoveAddress{NatWire.Var{0,10}},[],NatWire.decode([128,61,127,148,64,10]))

def result_code(result: NatWire.DecodeResult) -> U32:
  match result:
    case NatWire.ShortFrame{}:
      1
    case NatWire.InvalidFrame{}:
      2
    case NatWire.OtherFrame{}:
      3
    case NatWire.Decoded{_,_}:
      0

def reject(wire: List<&2,U32>, code: U32) -> Bool:
  U32.is_eq(result_code(NatWire.decode(wire)),code)

def absent(-A: Data, result: Maybe<&2,A>) -> Bool:
  match result:
    case None{}:
      True{}
    case Some{_}:
      False{}

def malformed_frames() -> Bool:
  reject([],1) &&
  reject([128,61,127],1) &&
  reject([128,61,127,148,192,0,0,0,0,0,0],1) &&
  reject([128,61,127,144,42,127,0,0],1) &&
  reject([128,61,127,145,42,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],1) &&
  reject([128,61,127,146,42,127,0,0,1,16],1) &&
  reject([128,61,127,146,42,127,0,0,1,16,256],2) &&
  reject([128,61,127,144,42,127,0,256,1,16,146],2) &&
  reject([128,61,127,148,64,256],2) &&
  reject([192,0,0,0,0,61,127,148,10],2) &&
  reject([1],3) &&
  reject([128,61,127,149],3) &&
  absent(List<&2,U32>,NatWire.encode(NatWire.RemoveAddress{NatWire.Var{1073741824,0}})) &&
  absent(List<&2,U32>,NatWire.encode(NatWire.AddAddress{NatWire.Var{0,42},NatWire.IPv4{[127,0,0]},4242})) &&
  absent(List<&2,U32>,NatWire.encode(NatWire.AddAddress{NatWire.Var{0,42},NatWire.IPv4{[127,0,0,256]},4242})) &&
  absent(List<&2,U32>,NatWire.encode(NatWire.ReachOut{NatWire.Var{0,42},NatWire.IPv4{[127,0,0,1]},65536}))

def limit_equal(expected: U32, actual: Maybe<&2,U32>) -> Bool:
  match actual:
    case Some{value}:
      U32.is_eq(expected,value)
    case None{}:
      False{}

def exact_limit(+value: U32) -> Bool:
  encoded([192,0,61,127,145,18,4,1,1,value],NatWire.encode_limit(value)) &&
    limit_equal(value,NatWire.decode_limit([value]))

def parameter_vectors() -> Bool:
  exact_limit(1) && exact_limit(63) && exact_limit(64) && exact_limit(255) &&
  absent(U32,NatWire.decode_limit([])) &&
  absent(U32,NatWire.decode_limit([0])) &&
  absent(U32,NatWire.decode_limit([256])) &&
  absent(U32,NatWire.decode_limit([64,64])) &&
  absent(List<&2,U32>,NatWire.encode_limit(0)) &&
  absent(List<&2,U32>,NatWire.encode_limit(256))

def require(message: String, ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print(String.append("PASS ",message))
    case False{}:
      IO.die(Unit,1,String.append("FAIL ",message))

def main() -> IO(Unit):
  do IO<Unit>:
    require("QUIC NAT traversal frame vectors",frame_vectors())
    require("QUIC NAT traversal sequence integer boundaries",sequence_vectors())
    require("QUIC NAT traversal malformed and unknown frames",malformed_frames())
    require("QUIC NAT traversal transport parameter",parameter_vectors())
    return Unit{}
