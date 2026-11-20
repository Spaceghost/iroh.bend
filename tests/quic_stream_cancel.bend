import Base
import ../src/quic_nat.bend as Wire

type Action is Data:
  Open{direction: U32}
  Accept{direction: U32}
  Write{byte: U32, fin: U32}
  Flush{}
  FinalWrite{count: Nat}
  FinAck{}
  ResetAck{}
  PendingNotice{message: String}
  Gate{message: String}
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
  Flag{value: U32}
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
   Check{Reset{zero},Error{32,""}},Check{FinAck{},Error{32,""}},Check{Write{7,0},Error{32,""}},
   Check{Read{},Byte{101}},Check{Read{},Fin{}},Check{Stop{zero},Error{32,""}},Check{Drop{},Complete{}},
   Check{Open{0},Handle{0}},Check{Write{2,0},Complete{}},Check{Flush{},Complete{}},
   Check{ReadDatagram{},Byte{12}},Check{Stop{Wire.Var{1073741824,0}},Error{22,""}},
   Check{Stop{large},Complete{}},Check{Stop{zero},Error{32,""}},
   Check{Read{},Fin{}},Check{Read{},Fin{}},Check{Write{102,1},Complete{}},Check{Flush{},Complete{}},Check{Drop{},Complete{}},
   Check{Accept{0},Handle{0}},Check{Read{},Byte{3}},Check{SendDatagram{13},Complete{}},
   Check{PeerReset{},Code{zero}},Check{Read{},Error{104,""}},Check{Read{},Fin{}},Check{PeerReset{},Code{zero}},Check{Stop{zero},Error{32,""}},Check{PeerStop{},NoCode{}},
   Check{Write{103,1},Complete{}},Check{Flush{},Complete{}},Check{Drop{},Complete{}},
   Check{Accept{0},Handle{0}},Check{Read{},Byte{4}},Check{Write{44,0},Complete{}},Check{Flush{},Complete{}},
   Check{PeerStop{},Code{Wire.Var{1,17}}},Check{FinAck{},Error{32,""}},Check{Write{7,0},Error{32,""}},
   Check{Read{},Byte{104}},Check{Read{},Fin{}},Check{Drop{},Complete{}},
   Check{Open{1},Handle{0}},Check{Stop{zero},Error{32,""}},Check{Reset{Wire.Var{0,63}},Complete{}},
   Check{Drop{},Complete{}},Check{Accept{1},Handle{0}},Check{Reset{zero},Error{32,""}},
   Check{PeerReset{},Code{Wire.Var{0,64}}},Check{Drop{},Complete{}},
   Check{Open{0},Handle{0}},Check{Write{5,0},Complete{}},Check{Flush{},Complete{}},
   Check{PeerReset{},Code{max}},Check{PeerStop{},Code{zero}},
   Check{Read{},Error{104,""}},Check{Write{7,0},Error{32,""}},Check{Drop{},Complete{}},
   Check{Accept{0},Handle{0}},Check{Read{},Byte{6}},Check{Reset{zero},Complete{}},
   Check{Stop{max},Complete{}},Check{Drop{},Complete{}},
   Check{SendDatagram{250},Complete{}},Check{ReadDatagram{},Byte{251}}]

def gate_before(enabled: Bool, message: String, rest: List<&2,Check>) -> List<&2,Check>:
  match enabled:
    case True{}:
      Con{Check{Gate{message},Complete{}},rest}
    case False{}:
      rest

def completion_round(+query: Action, end_stream: Action, after_send: Check, notice: String,
    +lose_ack: Bool, next: List<&2,Check>) -> List<&2,Check>:
  observed : List<&2,Check> = List.append(&2,Check,[Check{query,Flag{0}},Check{PendingNotice{notice},Complete{}},
    Check{query,Flag{1}},Check{Reset{Wire.Var{0,1}},Error{32,""}}],next)
  waiting : List<&2,Check> = gate_before(lose_ack,"WAIT_FOR_RECEIPT",observed)
  gate_before(lose_ack,"HOLD_ACKS",Con{Check{end_stream,Complete{}},Con{after_send,waiting}})

def completion_checks(+query: Action, first: Action, second: Action, +after_send: Check, +notice: String,
    +lose_ack: Bool) -> List<&2,Check>:
  last : List<&2,Check> = [Check{SendDatagram{52},Complete{}},Check{Drop{},Complete{}},Check{ReadDatagram{},Byte{53}},
    Check{Accept{1},Handle{0}},Check{query,Error{32,""}},Check{Read{},Byte{61}},
    Check{Read{},Fin{}},Check{Drop{},Complete{}},Check{SendDatagram{63},Complete{}},Check{ReadDatagram{},Byte{64}}]
  uni : List<&2,Check> = completion_round(query,second,after_send,notice,lose_ack,last)
  reply : List<&2,Check> = List.append(&2,Check,[Check{SendDatagram{42},Complete{}},Check{Read{},Byte{33}},Check{Read{},Fin{}},
    Check{query,Flag{1}},Check{Drop{},Complete{}},Check{ReadDatagram{},Byte{51}},Check{Open{1},Handle{0}},
    Check{query,Flag{0}}],uni)
  bidi : List<&2,Check> = completion_round(query,first,after_send,notice,lose_ack,reply)
  List.append(&2,Check,[Check{Open{0},Handle{0}},Check{query,Flag{0}},Check{Write{31,0},Complete{}},
    Check{Flush{},Complete{}},Check{ReadDatagram{},Byte{41}}],bidi)

def finish_checks() -> List<&2,Check>:
  completion_checks(FinAck{},FinalWrite{8192n},FinalWrite{0n},Check{Flush{},Complete{}},"FIN_PENDING",False{})

def reset_ack_checks(lose_ack: Bool) -> List<&2,Check>:
  completion_checks(ResetAck{},Reset{Wire.Var{1073741823,4294967295}},Reset{Wire.Var{0,0}},
    Check{FinAck{},Error{32,""}},"RESET_PENDING",lose_ack)

def Reply(-C: Type) -> Type:
  IO(C & State)

def gate_state(result: Result<&1,&1,U32 & String,String>) -> State:
  match result:
    case Done{"+"}:
      Complete{}
    case _:
      Unexpected{}

def read_gate(-C: Type, conn: C, raw: File & Result<&1,&1,U32 & String,String>) -> Reply(C):
  (file,result) = raw
  do IO<C & State>:
    File.close(file)
    return (conn,gate_state(result))

def gate(-C: Type, conn: C, message: String) -> Reply(C):
  do IO<C & State>:
    IO.print(message)
    file : File <- IO.try(File,File.open("/dev/stdin","r"))
    raw : File & Result<&1,&1,U32 & String,String> <- File.read(file,1)
    read_gate(C,conn,raw)

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
    case Flag{v} Flag{w}:
      U32.is_eq(v,w)
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
    case Flag{0} Flag{1}:
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
    IO.print("PASS stream checks and datagrams on the original connection")

def apply_check(-C: Type, engine: Driver<C>, conn: C, id: U32, check: Check) -> Reply(C):
  Driver{step,apply,_} = engine
  Check{action,_} = check
  do IO<C & State>:
    ready : C <- step(conn)
    apply(ready,id,action)

def expected(check: Check) -> State:
  Check{_,expect} = check
  expect

def report(-C: Type, status: State) -> IO(C):
  match status:
    case Error{number,message}:
      IO.die(C,number,message)
    case _:
      IO.die(C,1,"unexpected stream state or payload")

def failure(-C: Type, engine: Driver<C>, conn: C, index: U32, status: State) -> IO(C):
  Driver{_,_,close} = engine
  do IO<C>:
    close(conn)
    IO.print(String.append("stream check ",U32.show(index)))
    report(C,status)

def verdict(-C: Type, conn: C, id: U32, actual: State, equal: Bool, pending: Bool,
    good: C -> U32 -> IO(C), retry: C -> IO(C), bad: C -> State -> IO(C)) -> IO(C):
  match equal pending:
    case True{} _:
      good(conn,stream_id(actual,id))
    case False{} True{}:
      do IO<C>:
        IO.sleep(1)
        retry(conn)
    case False{} False{}:
      bad(conn,actual)

def result(-C: Type, reply: C & State, id: U32, +expect: State, good: C -> U32 -> IO(C),
    retry: C -> IO(C), bad: C -> State -> IO(C)) -> IO(C):
  (conn,+actual) = reply
  verdict(C,conn,id,actual,matches(expect,actual),waiting(actual,expect),good,retry,bad)

@unsafe def run_checks(~C: Type, ~engine: Driver<C>, conn: C, +id: U32, +index: U32, checks: List<&2,Check>, fuel: Nat)
    -> IO(C):
  match checks fuel:
    case Nil{} _:
      IO.pure(C,conn)
    case Con{_,_} 0n:
      failure(C,engine,conn,index,Pending{})
    case Con{+check,+rest} 1n+left:
      do IO<C>:
        raw : C & State <- apply_check(C,engine,conn,id,check)
        result(C,raw,id,expected(check),
          next => handle => run_checks(~C,~engine,next,handle,U32.add(index,1),rest,4000n),
          next => run_checks(~C,~engine,next,id,index,Con{check,rest},left),
          next => status => failure(C,engine,next,index,status))

@unsafe def advance(~C: Type, ~engine: Driver<C>, conn: C, id: U32, index: U32, checks: List<&2,Check>, fuel: Nat)
    -> IO(Unit):
  do IO<Unit>:
    done : C <- run_checks(~C,~engine,conn,id,index,checks,fuel)
    finish(C,engine,done)
