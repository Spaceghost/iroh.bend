import Base
import ../src/quic_nat.bend as Wire

type Action is Data:
  Open{direction: U32}
  Accept{direction: U32}
  Write{byte: U32, fin: U32}
  Flush{}
  Read{}
  SendDatagram{byte: U32}
  ReadDatagram{}
  Reset{code: Wire.VarInt}
  Stop{code: Wire.VarInt}
  PeerReset{}
  PeerStop{}
  Drop{}

type State is Data:
  Pending{}
  Complete{}
  Handle{id: U32}
  Byte{value: U32}
  Fin{}
  NoCode{}
  Code{value: Wire.VarInt}
  Error{number: U32, message: String}
  Unexpected{}

type Check is Data:
  Check{action: Action, expect: State}

def scenarios() -> List<&2,Check>:
  +max : Wire.VarInt = Wire.Var{1073741823,4294967295}
  +large : Wire.VarInt = Wire.Var{1193046,2309737967}
  +zero : Wire.VarInt = Wire.Var{0,0}
  [Check{Open{0},Handle{0}},Check{Write{1,0},Complete{}},Check{Flush{},Complete{}},
   Check{ReadDatagram{},Byte{11}},Check{PeerStop{},NoCode{}},Check{PeerReset{},NoCode{}},
   Check{Reset{Wire.Var{1073741824,0}},Error{22,""}},Check{Reset{max},Complete{}},
   Check{Reset{zero},Error{32,""}},Check{Write{7,0},Error{32,""}},
   Check{Read{},Byte{101}},Check{Read{},Fin{}},Check{Drop{},Complete{}},
   Check{Open{0},Handle{0}},Check{Write{2,0},Complete{}},Check{Flush{},Complete{}},
   Check{ReadDatagram{},Byte{12}},Check{Stop{large},Complete{}},Check{Stop{zero},Error{32,""}},
   Check{Read{},Error{32,""}},Check{Write{102,1},Complete{}},Check{Flush{},Complete{}},Check{Drop{},Complete{}},
   Check{Accept{0},Handle{0}},Check{Read{},Byte{3}},Check{SendDatagram{13},Complete{}},
   Check{PeerReset{},Code{zero}},Check{Read{},Error{104,""}},Check{PeerStop{},NoCode{}},
   Check{Write{103,1},Complete{}},Check{Flush{},Complete{}},Check{Drop{},Complete{}},
   Check{Accept{0},Handle{0}},Check{Read{},Byte{4}},Check{Write{44,0},Complete{}},Check{Flush{},Complete{}},
   Check{PeerStop{},Code{Wire.Var{1,17}}},Check{Write{7,0},Error{32,""}},
   Check{Read{},Byte{104}},Check{Read{},Fin{}},Check{Drop{},Complete{}},
   Check{Open{1},Handle{0}},Check{Stop{zero},Error{32,""}},Check{Reset{Wire.Var{0,63}},Complete{}},
   Check{Drop{},Complete{}},Check{Accept{1},Handle{0}},Check{Reset{zero},Error{32,""}},
   Check{PeerReset{},Code{Wire.Var{0,64}}},Check{Drop{},Complete{}},
   Check{Open{0},Handle{0}},Check{Write{5,0},Complete{}},Check{Flush{},Complete{}},
   Check{PeerReset{},Code{max}},Check{PeerStop{},Code{Wire.Var{1,17}}},
   Check{Read{},Error{104,""}},Check{Write{7,0},Error{32,""}},Check{Drop{},Complete{}},
   Check{Accept{0},Handle{0}},Check{Read{},Byte{6}},Check{Reset{zero},Complete{}},
   Check{Stop{large},Complete{}},Check{Drop{},Complete{}},
   Check{SendDatagram{250},Complete{}},Check{ReadDatagram{},Byte{251}}]

def Reply(-C: Type) -> Type:
  IO(C & State)

def answer(-C: Type, -T: Type, raw: C & Result<&1,&1,U32 & String,T>, convert: T -> State) -> Reply(C):
  match raw:
    case (conn,Done{value}):
      IO.pure(C & State,(conn,convert(value)))
    case (conn,Fail{(number,message)}):
      IO.pure(C & State,(conn,Error{number,message}))

def complete(unit: Unit) -> State:
  Complete{}

def queued(value: U32) -> State:
  match value:
    case 0:
      Pending{}
    case _:
      Complete{}

def handle(value: Maybe<&1,U32>) -> State:
  match value:
    case None{}:
      Pending{}
    case Some{id}:
      Handle{id}

def byte_value(bytes: List<&2,U32>) -> State:
  match bytes:
    case Con{byte,Nil{}}:
      Byte{byte}
    case _:
      Unexpected{}

def packet(value: Maybe<&1,List<&2,U32>>) -> State:
  match value:
    case None{}:
      Pending{}
    case Some{bytes}:
      byte_value(bytes)

def code(value: Maybe<&2,Wire.VarInt>) -> State:
  match value:
    case None{}:
      NoCode{}
    case Some{reason}:
      Code{reason}

def matches(want: State, actual: State) -> Bool:
  match want actual:
    case Complete{} Complete{}:
      True{}
    case Handle{_} Handle{_}:
      True{}
    case Byte{v} Byte{w}:
      U32.is_eq(v,w)
    case Fin{} Fin{}:
      True{}
    case NoCode{} NoCode{}:
      True{}
    case Code{Wire.Var{a,b}} Code{Wire.Var{c,d}}:
      U32.is_eq(a,c) && U32.is_eq(b,d)
    case Error{n,_} Error{m,_}:
      U32.is_eq(n,m)
    case _ _:
      False{}

def waiting(actual: State, want: State) -> Bool:
  match actual want:
    case Pending{} _:
      True{}
    case NoCode{} Code{_}:
      True{}
    case _ _:
      False{}

def stream_id(state: State, +old: U32) -> U32:
  match state:
    case Handle{id}:
      id
    case _:
      old

type Driver<-C: Type> is Type:
  Driver{step: C -> IO(C), apply: C -> U32 -> Action -> Reply(C), close: C -> IO(Unit)}

def finish(-C: Type, engine: Driver<C>, conn: C) -> IO(Unit):
  Driver{_,_,close} = engine
  do IO<Unit>:
    close(conn)
    IO.print("PASS both directions of stream cancellation and datagrams on the original connection")

def apply_check(-C: Type, engine: Driver<C>, conn: C, id: U32, check: Check) -> Reply(C):
  Driver{step,apply,_} = engine
  Check{action,_} = check
  do IO<C & State>:
    ready : C <- step(conn)
    apply(ready,id,action)

def expected(check: Check) -> State:
  Check{_,expect} = check
  expect

def report(status: State) -> IO(Unit):
  match status:
    case Error{number,message}:
      IO.die(Unit,number,message)
    case _:
      IO.die(Unit,1,"unexpected stream state or payload")

def failure(-C: Type, engine: Driver<C>, conn: C, index: U32, status: State) -> IO(Unit):
  Driver{_,_,close} = engine
  do IO<Unit>:
    close(conn)
    IO.print(String.append("stream cancellation check ",U32.show(index)))
    report(status)

def verdict(-C: Type, conn: C, id: U32, actual: State, equal: Bool, pending: Bool,
    good: C -> U32 -> IO(Unit), retry: C -> IO(Unit), bad: C -> State -> IO(Unit)) -> IO(Unit):
  match equal pending:
    case True{} _:
      good(conn,stream_id(actual,id))
    case False{} True{}:
      do IO<Unit>:
        IO.sleep(1)
        retry(conn)
    case False{} False{}:
      bad(conn,actual)

def result(-C: Type, reply: C & State, id: U32, +expect: State, good: C -> U32 -> IO(Unit),
    retry: C -> IO(Unit), bad: C -> State -> IO(Unit)) -> IO(Unit):
  (conn,+actual) = reply
  verdict(C,conn,id,actual,matches(expect,actual),waiting(actual,expect),good,retry,bad)

@unsafe def advance(~C: Type, ~engine: Driver<C>, conn: C, +id: U32, +index: U32, checks: List<&2,Check>, fuel: Nat)
    -> IO(Unit):
  match checks fuel:
    case Nil{} _:
      finish(C,engine,conn)
    case Con{_,_} 0n:
      failure(C,engine,conn,index,Pending{})
    case Con{+check,+rest} 1n+left:
      do IO<Unit>:
        raw : C & State <- apply_check(C,engine,conn,id,check)
        result(C,raw,id,expected(check),
          next => handle => advance(~C,~engine,next,handle,U32.add(index,1),rest,4000n),
          next => advance(~C,~engine,next,id,index,Con{check,rest},left),
          next => status => failure(C,engine,next,index,status))
