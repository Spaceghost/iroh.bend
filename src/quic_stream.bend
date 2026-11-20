import Base
import ./quic_nat.bend as Wire

def CodeResult(-C: Type) -> Type:
  C & Result<&1,&1,U32 & String,Maybe<&2,Wire.VarInt>>

def CodeWords(-C: Type) -> Type:
  C & Result<&1,&1,U32 & String,Maybe<&1,U32 & U32>>

def peer_code(-C: Type, raw: CodeWords(C)) -> IO(CodeResult(C)):
  match raw:
    case (conn,Done{Some{(high,low)}}):
      IO.pure(CodeResult(C),(conn,Done{Some{Wire.Var{high,low}}}))
    case (conn,Done{None{}}):
      IO.pure(CodeResult(C),(conn,Done{None{}}))
    case (conn,Fail{error}):
      IO.pure(CodeResult(C),(conn,Fail{error}))
