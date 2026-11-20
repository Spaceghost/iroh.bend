import Base
import ./quic_nat.bend as Wire
import ./quic_close.bend as Close

# ngtcp2's public close reason is limited to 1024 bytes. For a long peer close,
# recover the reason from the authenticated packet that the engine accepted.
# Read only frame boundaries. STREAM and DATAGRAM bodies are opaque.
type Application is Data:
  Received{code: Wire.VarInt, reason: List<&2,U32>}

type Step is Data:
  Next{rest: List<&2,U32>}
  PeerClose{code: Wire.VarInt, reason: List<&2,U32>, rest: List<&2,U32>}

def rest(value: Wire.IntegerInput) -> List<&2,U32>:
  match value:
    case Wire.Integer{_,_,tail}:
      tail
    case _:
      Nil{}

def skip_vars(count: Nat, bytes: List<&2,U32>) -> List<&2,U32>:
  match count bytes:
    case 0n tail:
      tail
    case 1n+left Nil{}:
      Nil{}
    case 1n+left Con{head,tail}:
      skip_vars(left,rest(Wire.split_integer(Con{head,tail})))

# Every frame and its declared body fit within one UDP payload.
def udp_count(size: U32, fits: Bool) -> Nat:
  match fits:
    case True{}:
      U32.to_nat(size)
    case False{}:
      65536n

def bounded(+size: U32) -> Nat:
  udp_count(size,U32.is_le(size,65535))

def skip_body(parsed: Wire.IntegerInput) -> List<&2,U32>:
  match parsed:
    case Wire.Integer{Wire.Var{0,+size},_,tail}:
      List.drop(&2,U32,tail,bounded(size))
    case _:
      Nil{}

def blob(prefix: Nat, bytes: List<&2,U32>) -> Step:
  Next{skip_body(Wire.split_integer(skip_vars(prefix,bytes)))}

def ack_ranges(parsed: Wire.IntegerInput, extra: Nat) -> Step:
  match parsed:
    case Wire.Integer{Wire.Var{0,+count},_,tail}:
      pairs = bounded(count)
      Next{skip_vars(Nat.add(Nat.mul(2n,pairs),1n+extra),tail)}
    case _:
      Next{[]}

def cid(bytes: List<&2,U32>) -> Step:
  match bytes:
    case Con{size,rest}:
      Next{List.drop(&2,U32,rest,Nat.add(U32.to_nat(size),16n))}
    case Nil{}:
      Next{[]}

def complete_body(code: Wire.VarInt, bytes: List<&2,U32>, tail: List<&2,U32>, complete: Bool) -> Step:
  match complete:
    case True{}:
      PeerClose{code,bytes,tail}
    case False{}:
      Next{[]}

def close_body(code: Wire.VarInt, length: Wire.IntegerInput) -> Step:
  match length:
    case Wire.Integer{Wire.Var{0,size},_,+tail}:
      +count = bounded(size)
      complete_body(code,List.take(&2,U32,tail,count),List.drop(&2,U32,tail,count),Nat.is_le(count,List.length(&2,U32,tail)))
    case _:
      Next{[]}

def app(parsed: Wire.IntegerInput) -> Step:
  match parsed:
    case Wire.Integer{code,_,tail}:
      close_body(code,Wire.split_integer(tail))
    case _:
      Next{[]}

def frame(kind: U32, bytes: List<&2,U32>) -> Step:
  match kind:
    case 0:
      Next{bytes}
    case 1:
      Next{bytes}
    case 2:
      ack_ranges(Wire.split_integer(skip_vars(2n,bytes)),0n)
    case 3:
      ack_ranges(Wire.split_integer(skip_vars(2n,bytes)),3n)
    case 4:
      Next{skip_vars(3n,bytes)}
    case 5:
      Next{skip_vars(2n,bytes)}
    case 6:
      blob(1n,bytes)
    case 7:
      blob(0n,bytes)
    case 10:
      blob(1n,bytes)
    case 11:
      blob(1n,bytes)
    case 14:
      blob(2n,bytes)
    case 15:
      blob(2n,bytes)
    case 16:
      Next{skip_vars(1n,bytes)}
    case 17:
      Next{skip_vars(2n,bytes)}
    case 18:
      Next{skip_vars(1n,bytes)}
    case 19:
      Next{skip_vars(1n,bytes)}
    case 20:
      Next{skip_vars(1n,bytes)}
    case 21:
      Next{skip_vars(2n,bytes)}
    case 22:
      Next{skip_vars(1n,bytes)}
    case 23:
      Next{skip_vars(1n,bytes)}
    case 24:
      cid(skip_vars(2n,bytes))
    case 25:
      Next{skip_vars(1n,bytes)}
    case 26:
      Next{List.drop(&2,U32,bytes,8n)}
    case 27:
      Next{List.drop(&2,U32,bytes,8n)}
    case 28:
      blob(2n,bytes)
    case 29:
      app(Wire.split_integer(bytes))
    case 30:
      Next{bytes}
    case 49:
      blob(0n,bytes)
    case _:
      # A lengthless STREAM or DATAGRAM consumes the rest of this packet.
      Next{[]}

def update(item: Step, last: Maybe<&2,Application>,
    again: List<&2,U32> -> Maybe<&2,Application> -> Maybe<&2,Application>)
    -> Maybe<&2,Application>:
  match item:
    case Next{tail}:
      again(tail,last)
    case PeerClose{code,bytes,tail}:
      again(tail,Some{Received{code,bytes}})

def scan(fuel: Nat, bytes: List<&2,U32>, last: Maybe<&2,Application>)
    -> Maybe<&2,Application>:
  match fuel bytes:
    case 0n _:
      last
    case 1n+left Nil{}:
      last
    case 1n+left Con{kind,tail}:
      update(frame(kind,tail),last,rest => next => scan(left,rest,next))

def application(+packet: List<&2,U32>) -> Maybe<&2,Application>:
  scan(List.length(&2,U32,packet),packet,None{})

def prefix_matches(prefix: List<&2,U32>, actual: List<&2,U32>) -> Bool:
  match prefix actual:
    case Nil{} _:
      True{}
    case Con{a,rest} Con{b,tail}:
      U32.is_eq(a,b) && prefix_matches(rest,tail)
    case _ _:
      False{}

def verified(code: Wire.VarInt, bytes: List<&2,U32>, valid: Bool) -> Close.ReadResult():
  match valid:
    case True{}:
      Done{Some{Close.ApplicationClosed{code,bytes}}}
    case False{}:
      Fail{(5,"QUIC close frame disagrees with the transport")}

def full(code: Wire.VarInt, prefix: List<&2,U32>, result: Maybe<&2,Application>) -> Close.ReadResult():
  match code result:
    case Wire.Var{+hi,+lo} Some{Received{Wire.Var{a,b},+bytes}}:
      verified(Wire.Var{hi,lo},bytes,U32.is_eq(hi,a) && U32.is_eq(lo,b) && prefix_matches(prefix,bytes))
    case _ None{}:
      Fail{(5,"missing application close frame")}

def unpack(-C: Type, raw: C & Result<&1,&1,U32 & String,List<&2,U32>>, code: Wire.VarInt, prefix: List<&2,U32>)
    -> C & Close.ReadResult():
  match raw:
    case (conn,Done{packet}):
      (conn,full(code,prefix,application(packet)))
    case (conn,Fail{why}):
      (conn,Fail{why})

def expand_peer(-C: Type, conn: C, code: Wire.VarInt, prefix: List<&2,U32>, clipped: Bool,
    packet: C -> IO(C & Result<&1,&1,U32 & String,List<&2,U32>>)) -> IO(C & Close.ReadResult()):
  match clipped:
    case False{}:
      IO.pure(C & Close.ReadResult(),(conn,Done{Some{Close.ApplicationClosed{code,prefix}}}))
    case True{}:
      do IO<C & Close.ReadResult()>:
        raw : C & Result<&1,&1,U32 & String,List<&2,U32>> <- packet(conn)
        return unpack(C,raw,code,prefix)

def expand(-C: Type, raw: C & Close.ReadResult(), packet: C -> IO(C & Result<&1,&1,U32 & String,List<&2,U32>>))
    -> IO(C & Close.ReadResult()):
  match raw:
    case (conn,Done{Some{Close.ApplicationClosed{code,+prefix}}}):
      expand_peer(C,conn,code,prefix,Nat.is_le(1024n,List.length(&2,U32,prefix)),packet)
    case other:
      IO.pure(C & Close.ReadResult(),other)
