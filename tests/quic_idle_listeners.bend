import Base
import ../src/quic_close.bend as Close
import ../src/quic_nat.bend as Wire

def progress(-C: Type) -> Type:
  C & Result<&1,&1,U32 & String,U32>

def expired(-C: Type, raw: progress(C), retry: C -> IO(C)) -> IO(C):
  match raw:
    case (conn,Fail{(110,_)}):
      IO.pure(C,conn)
    case (_,Fail{(code,why)}):
      IO.die(C,code,why)
    case (conn,Done{_}):
      do IO<C>:
        IO.sleep(1)
        retry(conn)

@unsafe def wait(~C: Type, ~step: C -> IO(progress(C)), conn: C, fuel: Nat) -> IO(C):
  match fuel:
    case 0n:
      IO.die(C,1,"short listener connection stayed open")
    case 1n+left:
      do IO<C>:
        raw : progress(C) <- step(conn)
        expired(C,raw,next => wait(~C,~step,next,left))

def close_wide(-C: Type, pair: C & Close.WriteResult(), drop: C -> IO(Unit)) -> IO(Unit):
  (conn,result) = pair
  do IO<Unit>:
    IO.try(Unit,IO.pure(Close.WriteResult(),result))
    drop(conn)

def serve_pair(~L: Type, ~C: Type, ~step: C -> IO(progress(C)),
    ~send_close: C -> Wire.VarInt -> List<&2,U32> -> IO(C & Close.WriteResult()),
    ~drop: C -> IO(Unit), ~close: L -> IO(Unit), wide: L & C, short: L & C) -> IO(Unit):
  (wide_listener,wide_conn) = wide
  (short_listener,short_conn) = short
  do IO<Unit>:
    ended : C <- wait(~C,~step,short_conn,6000n)
    drop(ended)
    done : C & Close.WriteResult() <- send_close(wide_conn,Wire.Var{0,123},[])
    close_wide(C,done,drop)
    close(short_listener)
    close(wide_listener)
    IO.print("PASS independent listener idle timeouts")

def accept_pair(~L: Type, ~C: Type, ~accept: L -> IO(L & C),
    ~serve: (L & C) -> (L & C) -> IO(Unit), wide: L & U32, short: L & U32) -> IO(Unit):
  (wide_listener,wide_port) = wide
  (short_listener,short_port) = short
  do IO<Unit>:
    IO.print(U32.show(wide_port))
    first : L & C <- accept(wide_listener)
    IO.print(U32.show(short_port))
    second : L & C <- accept(short_listener)
    serve(first,second)

def listeners(~L: Type, ~C: Type, ~bind: String -> Wire.VarInt -> IO(Result<&1,&1,U32 & String,L & U32>),
    ~accept: L -> IO(L & C), ~serve: (L & C) -> (L & C) -> IO(Unit), +host: String) -> IO(Unit):
  do IO<Unit>:
    wide : L & U32 <- IO.try(L & U32,bind(host,Wire.Var{1,123}))
    short : L & U32 <- IO.try(L & U32,bind(host,Wire.Var{0,1150}))
    accept_pair(~L,~C,~accept,~serve,wide,short)

def overflow(-C: Type, raw: Result<&1,&1,U32 & String,C>, release: C -> IO(Unit)) -> IO(Unit):
  match raw:
    case Fail{(75,_)}:
      IO.pure(Unit,Unit{})
    case Fail{(code,why)}:
      IO.die(Unit,code,why)
    case Done{value}:
      do IO<Unit>:
        release(value)
        IO.die(Unit,1,"unrepresentable idle timeout was accepted")

def close_bound(-L: Type, owner: L & U32, release: L -> IO(Unit)) -> IO(Unit):
  (listener,_) = owner
  release(listener)

def bound_limits(~L: Type, ~C: Type,
    ~bind: Wire.VarInt -> IO(Result<&1,&1,U32 & String,L & U32>),
    ~start: U32 -> Wire.VarInt -> IO(Result<&1,&1,U32 & String,C>),
    ~release_listener: L -> IO(Unit), ~release_conn: C -> IO(Unit), bound: L & U32, +largest: Wire.VarInt, +excess: Wire.VarInt) -> IO(Unit):
  (owner,+port) = bound
  do IO<Unit>:
    valid : C <- IO.try(C,start(port,largest))
    release_conn(valid)
    invalid : Result<&1,&1,U32 & String,C> <- start(port,excess)
    overflow(C,invalid,release_conn)
    invalid_bind : Result<&1,&1,U32 & String,L & U32> <- bind(excess)
    overflow(L & U32,invalid_bind,pair => close_bound(L,pair,release_listener))
    release_listener(owner)
    IO.print("PASS exact native idle timer limit and overflow")

def limits(~L: Type, ~C: Type,
    ~bind: Wire.VarInt -> IO(Result<&1,&1,U32 & String,L & U32>),
    ~start: U32 -> Wire.VarInt -> IO(Result<&1,&1,U32 & String,C>),
    ~release_listener: L -> IO(Unit), ~release_conn: C -> IO(Unit), +largest: Wire.VarInt, +excess: Wire.VarInt) -> IO(Unit):
  do IO<Unit>:
    bound : L & U32 <- IO.try(L & U32,bind(largest))
    bound_limits(~L,~C,~bind,~start,~release_listener,~release_conn,bound,largest,excess)
