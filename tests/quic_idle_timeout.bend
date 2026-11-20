import Base
import ./quic_connection_close.bend as CloseTest
import ./quic_stream_cancel.bend as Stream
import ../src/quic_close.bend as Close
import ../src/quic_nat.bend as Wire

def packets(listener: Bool, +index: U32) -> List<&2,Stream.Check>:
  match listener:
    case True{}:
      [Stream.Check{Stream.ReadDatagram{},Stream.Byte{U32.add(10,index)}},
       Stream.Check{Stream.SendDatagram{U32.add(20,index)},Stream.Complete{}}]
    case False{}:
      [Stream.Check{Stream.SendDatagram{U32.add(10,index)},Stream.Complete{}},
       Stream.Check{Stream.ReadDatagram{},Stream.Byte{U32.add(20,index)}}]

def pause(listener: Bool) -> IO(Unit):
  match listener:
    case True{}:
      IO.pure(Unit,Unit{})
    case False{}:
      IO.sleep(300)

@unsafe def traffic(~C: Type, ~driver: Stream.Driver<C>, conn: C, +listener: Bool, +index: U32, more: Nat) -> IO(C):
  do IO<C>:
    echoed : C <- Stream.run_checks(~C,~driver,conn,0,1,packets(listener,index),4000n)
    another(C,echoed,more,next => left => traffic(~C,~driver,next,listener,U32.add(index,1),left),listener)

def another(-C: Type, conn: C, more: Nat, next: C -> Nat -> IO(C), listener: Bool) -> IO(C):
  match more:
    case 0n:
      IO.pure(C,conn)
    case 1n+left:
      do IO<C>:
        pause(listener)
        next(conn,left)

def expiry(-C: Type, raw: C & Result<&1,&1,U32 & String,U32>, next: C -> IO(C)) -> IO(C):
  match raw:
    case (conn,Fail{(110,_)}):
      IO.pure(C,conn)
    case (_,Fail{(code,message)}):
      IO.die(C,code,message)
    case (conn,Done{_}):
      do IO<C>:
        IO.sleep(1)
        next(conn)

@unsafe def wait(~C: Type, ~ops: CloseTest.Operations<C>, conn: C, fuel: Nat) -> IO(C):
  match fuel:
    case 0n:
      IO.die(C,1,"established connection never reached idle timeout")
    case 1n+left:
      do IO<C>:
        raw : C & Result<&1,&1,U32 & String,U32> <- CloseTest.pump(C,ops,conn)
        expiry(C,raw,next => wait(~C,~ops,next,left))

def timed_out(-C: Type, raw: C & Close.ReadResult()) -> IO(C):
  match raw:
    case (conn,Done{Some{Close.TimedOut{}}}):
      IO.pure(C,conn)
    case _:
      IO.die(C,1,"expected the public TimedOut close reason")

def operation(-C: Type, raw: C & Stream.State) -> IO(C):
  match raw:
    case (conn,Stream.Error{110,_}):
      IO.pure(C,conn)
    case _:
      IO.die(C,1,"expected ETIMEDOUT on I/O after idle expiry")

def rejected(-C: Type, driver: Stream.Driver<C>, conn: C, action: Stream.Action) -> IO(C):
  Stream.Driver{_,apply,_} = driver
  do IO<C>:
    raw : C & Stream.State <- apply(conn,0,action)
    operation(C,raw)

def release(-C: Type, driver: Stream.Driver<C>, conn: C) -> IO(Unit):
  Stream.Driver{_,_,drop} = driver
  drop(conn)

@unsafe def finish(~C: Type, ~ops: CloseTest.Operations<C>, ~driver: Stream.Driver<C>, conn: C, name: String) -> IO(Unit):
  do IO<Unit>:
    first : C & Close.ReadResult() <- CloseTest.inspect(C,ops,conn)
    expired : C <- timed_out(C,first)
    a : C <- rejected(C,driver,expired,Stream.ReadDatagram{})
    b : C <- rejected(C,driver,a,Stream.SendDatagram{99})
    c : C <- rejected(C,driver,b,Stream.Open{1})
    again : C & Close.ReadResult() <- CloseTest.inspect(C,ops,c)
    stable : C <- timed_out(C,again)
    closed : C & Close.WriteResult() <- CloseTest.transmit(C,ops,stable,Wire.Var{0,1},[])
    local : C <- CloseTest.submitted(C,closed,False{})
    reason : C & Close.ReadResult() <- CloseTest.inspect(C,ops,local)
    done : C <- CloseTest.terminal(C,reason,True{},0)
    release(C,driver,done)
    IO.print(String.append("PASS ",String.append(name," timed out")))

type Mode is Data:
  Idle{}
  Activity{}
  OneWay{}
  Defaults{}

def repetitions(mode: Mode) -> Nat:
  match mode:
    case Activity{}:
      4n
    case _:
      0n

@unsafe def reply(~C: Type, ~driver: Stream.Driver<C>, conn: C) -> IO(C):
  do IO<C>:
    IO.print("READY")
    Stream.run_checks(~C,~driver,conn,0,1,[Stream.Check{Stream.ReadDatagram{},Stream.Byte{31}},
      Stream.Check{Stream.SendDatagram{32},Stream.Complete{}}],13000n)

@unsafe def expired(~C: Type, ~ops: CloseTest.Operations<C>, ~driver: Stream.Driver<C>, conn: C,
    name: String) -> IO(Unit):
  do IO<Unit>:
    last : Nat <- IO.now()
    pending : C & Close.ReadResult() <- CloseTest.inspect(C,ops,conn)
    open : C <- CloseTest.initial(C,pending)
    end_conn : C <- wait(~C,~ops,open,6000n)
    now : Nat <- IO.now()
    checked : C <- CloseTest.require(C,end_conn,Nat.is_ge(now,Nat.add(last,700n)),
      "idle timeout before the negotiated deadline")
    finish(~C,~ops,~driver,checked,name)

@unsafe def scenario(~C: Type, ~ops: CloseTest.Operations<C>, ~driver: Stream.Driver<C>, conn: C, mode: Mode) -> IO(Unit):
  match mode:
    case Defaults{}:
      do IO<Unit>:
        answered : C <- reply(~C,~driver,conn)
        closed : C <- CloseTest.wait(~C,~ops,answered,0,5000n)
        release(C,driver,closed)
        IO.print("PASS defaults kept alive")
    case OneWay{}:
      do IO<Unit>:
        answered : C <- reply(~C,~driver,conn)
        expired(~C,~ops,~driver,answered,"one-way")
    case Activity{}:
      expired(~C,~ops,~driver,conn,"activity")
    case Idle{}:
      expired(~C,~ops,~driver,conn,"idle")

@unsafe def exchange(~C: Type, ~ops: CloseTest.Operations<C>, ~driver: Stream.Driver<C>, conn: C,
    listener: Bool, +mode: Mode) -> IO(Unit):
  do IO<Unit>:
    before : C & Close.ReadResult() <- CloseTest.inspect(C,ops,conn)
    active : C <- CloseTest.initial(C,before)
    echoed : C <- traffic(~C,~driver,active,listener,0,repetitions(mode))
    scenario(~C,~ops,~driver,echoed,mode)
