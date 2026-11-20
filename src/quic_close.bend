import Base
import ./quic_nat.bend as Wire

type Reason is Data:
  LocallyClosed{}
  ApplicationClosed{code: Wire.VarInt, reason: List<&2,U32>}

def WriteResult() -> Type:
  Result<&1,&1,U32 & String,Unit>

def ReadResult() -> Type:
  Result<&1,&1,U32 & String,Maybe<&2,Reason>>

# The outer option denotes closure. The inner option carries the peer's code and bytes.
def NativeResult() -> Type:
  Result<&1,&1,U32 & String,Maybe<&1,Maybe<&1,(U32 & U32) & List<&2,U32>>>>

def decode(raw: NativeResult()) -> ReadResult():
  match raw:
    case Done{None{}}:
      Done{None{}}
    case Done{Some{None{}}}:
      Done{Some{LocallyClosed{}}}
    case Done{Some{Some{((high,low),reason)}}}:
      Done{Some{ApplicationClosed{Wire.Var{high,low},reason}}}
    case Fail{error}:
      Fail{error}

def checked(-C: Type, conn: C, high: U32, low: U32, reason: List<&2,U32>, valid: Bool,
    send: C -> U32 -> U32 -> List<&2,U32> -> IO(C & WriteResult())) -> IO(C & WriteResult()):
  match valid:
    case False{}:
      IO.pure(C & WriteResult(),(conn,Fail{(22,"invalid QUIC application close code or reason byte")}))
    case True{}:
      # Both native send buffers hold at most 1500 reason bytes before packet overhead.
      send(conn,high,low,List.take(&2,U32,reason,1500n))

def close(-C: Type, conn: C, code: Wire.VarInt, +reason: List<&2,U32>,
    send: C -> U32 -> U32 -> List<&2,U32> -> IO(C & WriteResult())) -> IO(C & WriteResult()):
  Wire.Var{+high,low} = code
  checked(C,conn,high,low,reason,U32.is_le(high,1073741823) && List.all(&2,U32,b => U32.is_le(b,255),reason),send)

def result(-C: Type, pair: C & NativeResult()) -> C & ReadResult():
  (conn,status) = pair
  (conn,decode(status))

def observe(-C: Type, conn: C, read: C -> IO(C & NativeResult())) -> IO(C & ReadResult()):
  do IO<C & ReadResult()>:
    raw : C & NativeResult() <- read(conn)
    return result(C,raw)
