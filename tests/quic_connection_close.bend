import Base
import ../src/quic_close.bend as Close
import ../src/quic_nat.bend as Wire
import ./quic_stream_cancel.bend as Stream

type Operations<-C: Type> is Type:
  Operations{close: C -> Wire.VarInt -> List<&2,U32> -> IO(C & Close.WriteResult()),
    reason: C -> IO(C & Close.ReadResult()), step: C -> IO(C & Result<&1,&1,U32 & String,U32>)}

def inspect(-C: Type, ops: Operations<C>, conn: C) -> IO(C & Close.ReadResult()):
  Operations{_,read,_} = ops
  read(conn)

def transmit(-C: Type, ops: Operations<C>, conn: C, code: Wire.VarInt, bytes: List<&2,U32>) -> IO(C & Close.WriteResult()):
  Operations{close,_,_} = ops
  close(conn,code,bytes)

def pump(-C: Type, ops: Operations<C>, conn: C) -> IO(C & Result<&1,&1,U32 & String,U32>):
  Operations{_,_,step} = ops
  step(conn)

def pattern(left: Nat, +next: U32) -> List<&2,U32>:
  match left:
    case 0n:
      Nil{}
    case 1n+n:
      Con{next,pattern(n,U32.mod(U32.add(next,1),251))}

def example(id: U32) -> Wire.VarInt & List<&2,U32>:
  match id:
    case 0:
      (Wire.Var{0,0},[])
    case 1:
      (Wire.Var{0,42},[116,104,97,110,107,115,44,32,98,121,101,33])
    case 2:
      (Wire.Var{1073741823,4294967295},[0,255,29,0,128,42,0])
    case 3:
      (Wire.Var{0,16384},pattern(1100n,0))
    case _:
      (Wire.Var{0,42},pattern(4096n,0))

def equal(actual: List<&2,U32>, expected: List<&2,U32>) -> Bool:
  match actual expected:
    case Nil{} Nil{}:
      True{}
    case Con{a,rest} Con{b,tail}:
      U32.is_eq(a,b) && equal(rest,tail)
    case _ _:
      False{}

def reason_bytes(+id: U32, +actual: List<&2,U32>, expected: List<&2,U32>) -> Bool:
  match id:
    case 4:
      +size = List.length(&2,U32,actual)
      Nat.is_le(1024n,size) && Nat.is_lt(size,4096n) && equal(actual,List.take(&2,U32,expected,size))
    case _:
      equal(actual,expected)

def received(id: U32, code: Wire.VarInt, bytes: List<&2,U32>, want: Wire.VarInt & List<&2,U32>) -> Bool:
  Wire.Var{hi,lo} = code
  (Wire.Var{want_hi,want_lo},expected) = want
  U32.is_eq(hi,want_hi) && U32.is_eq(lo,want_lo) && reason_bytes(id,bytes,expected)

def require(-C: Type, conn: C, valid: Bool, message: String) -> IO(C):
  match valid:
    case True{}:
      IO.pure(C,conn)
    case False{}:
      IO.die(C,1,message)

def initial(-C: Type, pair: C & Close.ReadResult()) -> IO(C):
  match pair:
    case (conn,Done{None{}}):
      IO.pure(C,conn)
    case (conn,_):
      IO.die(C,1,"expected an open connection")

def submitted(-C: Type, pair: C & Close.WriteResult(), invalid: Bool) -> IO(C):
  match pair invalid:
    case (conn,Done{Unit{}}) False{}:
      IO.pure(C,conn)
    case (conn,Fail{(22,_)}) True{}:
      IO.pure(C,conn)
    case (conn,Fail{(code,why)}) _:
      IO.die(C,code,why)
    case (conn,_) _:
      IO.die(C,1,"invalid application close was accepted")

def terminal(-C: Type, pair: C & Close.ReadResult(), local: Bool, +id: U32) -> IO(C):
  match pair local:
    case (conn,Done{Some{Close.LocallyClosed{}}}) True{}:
      IO.pure(C,conn)
    case (conn,Done{Some{Close.ApplicationClosed{code,bytes}}}) False{}:
      require(C,conn,received(id,code,bytes,example(id)),"incorrect peer application close code or reason")
    case (conn,Fail{(code,why)}) _:
      IO.die(C,code,why)
    case (conn,_) _:
      IO.die(C,1,"unexpected connection close reason")

def stepped(-C: Type, raw: C & Result<&1,&1,U32 & String,U32>) -> C:
  (next,_) = raw
  next

def observed(-C: Type, pair: C & Close.ReadResult(), id: U32, retry: C -> IO(C)) -> IO(C):
  match pair:
    case (conn,Done{None{}}):
      do IO<C>:
        IO.sleep(1)
        retry(conn)
    case result:
      terminal(C,result,False{},id)

@unsafe def wait(~C: Type, ~ops: Operations<C>, conn: C, +id: U32, fuel: Nat) -> IO(C):
  match fuel:
    case 0n:
      IO.die(C,1,"peer application close timed out")
    case 1n+left:
      do IO<C>:
        raw : C & Result<&1,&1,U32 & String,U32> <- pump(C,ops,conn)
        pair : C & Close.ReadResult() <- inspect(C,ops,stepped(C,raw))
        observed(C,pair,id,next => wait(~C,~ops,next,id,left))

def send_example(-C: Type, conn: C, close: C -> Wire.VarInt -> List<&2,U32> -> IO(C & Close.WriteResult()),
    data: Wire.VarInt & List<&2,U32>) -> IO(C):
  (code,bytes) = data
  do IO<C>:
    raw : C & Close.WriteResult() <- close(conn,code,bytes)
    submitted(C,raw,False{})

@unsafe def first(~C: Type, ~ops: Operations<C>, conn: C, send: Bool, +id: U32) -> IO(C):
  match send:
    case True{}:
      send_example(C,conn,c => hi => data => transmit(C,ops,c,hi,data),example(id))
    case False{}:
      wait(~C,~ops,conn,id,5000n)

def cannot_write(-C: Type, result: C & Stream.State) -> IO(C):
  match result:
    case (conn,Stream.Error{_,_}):
      IO.pure(C,conn)
    case (conn,_):
      IO.die(C,1,"closed connection accepted a datagram")

@unsafe def finish_close(~C: Type, ~ops: Operations<C>, driver: Stream.Driver<C>, conn: C, +send: Bool, +id: U32) -> IO(Unit):
  Stream.Driver{_,apply,drop} = driver
  do IO<Unit>:
    first_seen : C <- first(~C,~ops,conn,send,id)
    reason : C & Close.ReadResult() <- inspect(C,ops,first_seen)
    same : C <- terminal(C,reason,send,id)
    rejected : C & Stream.State <- apply(same,0,Stream.SendDatagram{17})
    closed : C <- cannot_write(C,rejected)
    again : C & Close.WriteResult() <- transmit(C,ops,closed,Wire.Var{0,1},[105,103,110,111,114,101,100])
    unchanged : C <- submitted(C,again,False{})
    last : C & Close.ReadResult() <- inspect(C,ops,unchanged)
    done : C <- terminal(C,last,True{},id)
    drop(done)
    IO.print(String.append("PASS close ",U32.show(id)))

def write_message(bytes: List<&2,U32>) -> List<&2,Stream.Check>:
  match bytes:
    case Nil{}:
      Nil{}
    case Con{b,Nil{}}:
      [Stream.Check{Stream.Write{b,1},Stream.Complete{}},Stream.Check{Stream.Flush{},Stream.Complete{}}]
    case Con{b,tail}:
      Con{Stream.Check{Stream.Write{b,0},Stream.Complete{}},Con{Stream.Check{Stream.Flush{},Stream.Complete{}},write_message(tail)}}

def read_message(bytes: List<&2,U32>) -> List<&2,Stream.Check>:
  match bytes:
    case Nil{}:
      [Stream.Check{Stream.Read{},Stream.Fin{}}]
    case Con{b,tail}:
      Con{Stream.Check{Stream.Read{},Stream.Byte{b}},read_message(tail)}

def hello() -> List<&2,U32>:
  [72,101,108,108,111,44,32,119,111,114,108,100,33]

def echo(send: Bool, +message: List<&2,U32>) -> List<&2,Stream.Check>:
  match send:
    case True{}:
      Con{Stream.Check{Stream.Open{0},Stream.Handle{0}},List.append(&2,Stream.Check,write_message(message),read_message(message))}
    case False{}:
      Con{Stream.Check{Stream.Accept{0},Stream.Handle{0}},List.append(&2,Stream.Check,read_message(message),write_message(message))}

@unsafe def exchange(~C: Type, ~ops: Operations<C>, ~driver: Stream.Driver<C>, conn: C, +send: Bool, +id: U32) -> IO(Unit):
  do IO<Unit>:
    bad_code : C & Close.WriteResult() <- transmit(C,ops,conn,Wire.Var{1073741824,0},[])
    a : C <- submitted(C,bad_code,True{})
    bad_bytes : C & Close.WriteResult() <- transmit(C,ops,a,Wire.Var{0,42},[0,256])
    b : C <- submitted(C,bad_bytes,True{})
    status : C & Close.ReadResult() <- inspect(C,ops,b)
    open : C <- initial(C,status)
    ready : C <- Stream.run_checks(~C,~driver,open,0,1,echo(send,hello()),4000n)
    finish_close(~C,~ops,driver,ready,send,id)
