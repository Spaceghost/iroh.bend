import Base
import ../src/quic_multipath.bend as Q
import ../src/quic_nat.bend as Wire
import ./quic_multipath_bend.bend as Peer
import ./quic_multipath_listener.bend as Listener

def check_path(conn: Q.MultipathConnection, path: U32) -> IO(Q.MultipathConnection & U32):
  do IO<Q.MultipathConnection & U32>:
    result : Q.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Q.multipath_status(conn,path)
    Peer.ok(U32,result)

def read_echo(sent: Q.MultipathConnection & U32, value: U32) -> IO(Q.MultipathConnection):
  (conn,+stream) = sent
  do IO<Q.MultipathConnection>:
    read : Q.MultipathConnection <- Peer.receive(2500n,conn,stream,value,False{})
    Peer.release(read,stream)

def exchange(conn: Q.MultipathConnection, path: U32, +value: U32) -> IO(Q.MultipathConnection):
  do IO<Q.MultipathConnection>:
    opened : Q.MultipathConnection & U32 <- Peer.open(conn)
    sent : Q.MultipathConnection & U32 <- Peer.send(opened,path,value)
    read_echo(sent,value)

def set_idle(conn: Q.MultipathConnection, path: U32, idle_ms: U32) -> IO(Q.MultipathConnection):
  do IO<Q.MultipathConnection>:
    result : Q.MultipathConnection & Result<&1,&1,U32 & String,Unit> <- Q.set_multipath_path_idle_timeout(conn,path,idle_ms)
    ready : Q.MultipathConnection & Unit <- Peer.ok(Unit,result)
    return Peer.released(ready)

def announce(label: String, path: U32) -> IO(Unit):
  IO.print(String.append(label,U32.show(path)))

def echo(conn: Q.MultipathConnection, byte: U32, path: U32) -> IO(Q.MultipathConnection):
  do IO<Q.MultipathConnection>:
    opened : Q.MultipathConnection & U32 <- Listener.incoming(4000n,conn,0)
    Listener.echo(opened,path,byte)

def retain(conn: Q.MultipathConnection, dialer: Bool) -> IO(Q.MultipathConnection):
  match dialer:
    case True{}:
      exchange(conn,0,11)
    case False{}:
      IO.pure(Q.MultipathConnection,conn)

def fresh_data(conn: Q.MultipathConnection, dialer: Bool) -> IO(Q.MultipathConnection):
  match dialer:
    case True{}:
      exchange(conn,0,77)
    case False{}:
      echo(conn,77,0)

def idle_steps(fuel: Nat, conn: Q.MultipathConnection) -> IO(Q.MultipathConnection):
  match fuel:
    case 0n:
      IO.pure(Q.MultipathConnection,conn)
    case 1n+rest:
      do IO<Q.MultipathConnection>:
        stepped : Q.MultipathConnection <- Peer.step(conn)
        IO.sleep(5)
        idle_steps(rest,stepped)

def survival(pair: Q.MultipathConnection & U32, reply: Q.MultipathConnection -> IO(Q.MultipathConnection)) -> IO(Unit):
  match pair:
    case (conn,1):
      do IO<Unit>:
        finished : Q.MultipathConnection <- reply(conn)
        flushed : Q.MultipathConnection <- idle_steps(20n,finished)
        IO.print("SURVIVOR 0")
        Q.close_multipath(flushed)
    case (conn,_):
      Peer.reject(Unit,conn,1,"the original path was lost")

def expiry_progress(progress: Q.MultipathConnection & U32, path: U32, dialer: Bool,
    retry: Q.MultipathConnection -> IO(Unit)) -> IO(Unit):
  match progress:
    case (conn,3):
      do IO<Unit>:
        announce("EXPIRED ",path)
        original : Q.MultipathConnection & U32 <- check_path(conn,0)
        survival(original,c => fresh_data(c,dialer))
    case (conn,_):
      do IO<Unit>:
        alive : Q.MultipathConnection <- retain(conn,dialer)
        IO.sleep(25)
        retry(alive)

def await_expiry(fuel: Nat, conn: Q.MultipathConnection, +path: U32, +dialer: Bool) -> IO(Unit):
  match fuel:
    case 0n:
      Peer.reject(Unit,conn,1,"the alternate path stayed open")
    case 1n+rest:
      do IO<Unit>:
        stepped : Q.MultipathConnection <- Peer.step(conn)
        progress : Q.MultipathConnection & U32 <- check_path(stepped,path)
        expiry_progress(progress,path,dialer,next => await_expiry(rest,next,path,dialer))

def validated(conn: Q.MultipathConnection, +path: U32, mode: Bool) -> IO(Q.MultipathConnection):
  match mode:
    case True{}:
      do IO<Q.MultipathConnection>:
        ready : Q.MultipathConnection <- Peer.wait_path(2500n,conn,path)
        exchange(ready,path,22)
    case False{}:
      IO.pure(Q.MultipathConnection,conn)

def dial_candidate(opened: Q.MultipathConnection & U32, idle_ms: U32, validate: Bool) -> IO(Unit):
  (conn,+path) = opened
  do IO<Unit>:
    ready : Q.MultipathConnection <- validated(conn,path,validate)
    original : Q.MultipathConnection <- set_idle(ready,0,1200)
    configured : Q.MultipathConnection <- set_idle(original,path,idle_ms)
    announce("CANDIDATE ",path)
    await_expiry(1200n,configured,path,True{})

def dial(+host: String, port: U32, secondary: U32, idle_ms: U32, validate: Bool) -> IO(Unit):
  do IO<Unit>:
    conn : Q.MultipathConnection <- IO.try(Q.MultipathConnection,
      Q.connect_multipath(host,port,List.replicate(U32,32n,73),Peer.fixture_key(0),"iroh-bend/compat/1",3000n))
    primed : Q.MultipathConnection <- exchange(conn,0,11)
    opened : Q.MultipathConnection & U32 <- Peer.probe(2000n,primed,host,secondary)
    dial_candidate(opened,idle_ms,validate)

def listen_candidate(ready: Q.MultipathConnection & U32, idle_ms: U32) -> IO(Unit):
  (conn,+path) = ready
  do IO<Unit>:
    used : Q.MultipathConnection <- echo(conn,22,path)
    original : Q.MultipathConnection <- set_idle(used,0,1200)
    configured : Q.MultipathConnection <- set_idle(original,path,idle_ms)
    announce("CANDIDATE ",path)
    await_expiry(1200n,configured,path,False{})

def serve(pair: Q.MultipathListener & Q.MultipathConnection, idle_ms: U32) -> IO(Unit):
  (listener,conn) = pair
  do IO<Unit>:
    Q.close_multipath_listener(listener)
    primed : Q.MultipathConnection <- echo(conn,11,0)
    candidate : Q.MultipathConnection & U32 <- Listener.wait_path(4000n,primed)
    listen_candidate(candidate,idle_ms)

def wait_for_accept(bound: Q.MultipathListener & U32, idle_ms: U32) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    accepted : Q.MultipathListener & Q.MultipathConnection <- Listener.accept(4000n,listener)
    serve(accepted,idle_ms)

def listen(host: String, idle_ms: U32) -> IO(Unit):
  do IO<Unit>:
    bound : Q.MultipathListener & U32 <- IO.try(Q.MultipathListener & U32,
      Q.bind_multipath(host,0,List.replicate(U32,32n,73),Peer.fixture_key(0),"iroh-bend/compat/1"))
    wait_for_accept(bound,idle_ms)

def dial_options(host: String, port: Maybe<&2,U32>, secondary: Maybe<&2,U32>, idle: Maybe<&2,U32>, validate: Bool) -> IO(Unit):
  match port secondary idle:
    case Some{primary} Some{alternate} Some{idle_ms}:
      dial(host,primary,alternate,idle_ms,validate)
    case _ _ _:
      IO.die(Unit,2,"expected numeric ports and timeout")

def last_path(host: String, port: U32) -> IO(Unit):
  do IO<Unit>:
    conn : Q.MultipathConnection <- IO.try(Q.MultipathConnection,
      Q.connect_multipath(host,port,List.replicate(U32,32n,73),Peer.fixture_key(0),"iroh-bend/compat/1",3000n))
    primed : Q.MultipathConnection <- exchange(conn,0,11)
    configured : Q.MultipathConnection <- set_idle(primed,0,25)
    IO.print("LAST PATH 0")
    waited : Q.MultipathConnection <- idle_steps(300n,configured)
    progress : Q.MultipathConnection & U32 <- check_path(waited,0)
    survival(progress,c => exchange(c,0,77))

def single_path_progress(progress: Q.MultipathConnection & Result<&1,&1,U32 & String,U32>,
    +ready: Bool, retry: Q.MultipathConnection -> Bool -> IO(Unit)) -> IO(Unit):
  match progress ready:
    case (conn,Done{0}) False{}:
      do IO<Unit>:
        IO.sleep(5)
        retry(conn,False{})
    case (conn,Done{1}) False{}:
      do IO<Unit>:
        IO.print("SINGLE PATH")
        retry(conn,True{})
    case (conn,Done{1}) True{}:
      do IO<Unit>:
        IO.sleep(5)
        retry(conn,True{})
    case (conn,Fail{(110,_)}) True{}:
      do IO<Unit>:
        Q.close_multipath(conn)
        IO.print("CONNECTION TIMED OUT")
    case (conn,_) _:
      Peer.reject(Unit,conn,1,"unexpected result from base QUIC")

def single_path_steps(fuel: Nat, conn: Q.MultipathConnection, ready: Bool) -> IO(Unit):
  match fuel:
    case 0n:
      Peer.reject(Unit,conn,1,"base QUIC did not time out")
    case 1n+rest:
      do IO<Unit>:
        progress : Q.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Q.step_multipath(conn)
        single_path_progress(progress,ready,next => state => single_path_steps(rest,next,state))

def single_path(host: String, port: U32) -> IO(Unit):
  do IO<Unit>:
    conn : Q.MultipathConnection <- IO.try(Q.MultipathConnection,
      Q.start_multipath_bytes_with_idle_timeout(host,port,List.replicate(U32,32n,73),Peer.fixture_key(0),Peer.text_alpn(),Wire.Var{0,1200}))
    single_path_steps(1000n,conn,False{})

def one_path(host: String, port: Maybe<&2,U32>, last: Bool) -> IO(Unit):
  match port last:
    case Some{number} True{}:
      last_path(host,number)
    case Some{number} False{}:
      single_path(host,number)
    case None{} _:
      IO.die(Unit,2,"expected a numeric port")

def listen_options(host: String, idle: Maybe<&2,U32>) -> IO(Unit):
  match idle:
    case Some{idle_ms}:
      listen(host,idle_ms)
    case None{}:
      IO.die(Unit,2,"expected a numeric timeout")

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,host,port,secondary,idle,mode]:
      dial_options(host,U32.read(port),U32.read(secondary),U32.read(idle),String.eq(mode,"validated"))
    case [_,host,port,mode]:
      one_path(host,U32.read(port),String.eq(mode,"last"))
    case [_,host,idle]:
      listen_options(host,U32.read(idle))
    case _:
      IO.die(Unit,2,"expected a listener or dialer address")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
