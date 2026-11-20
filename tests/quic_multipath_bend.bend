import Base
import ../src/quic_multipath.bend as Quic

def reject(-T: Type, conn: Quic.MultipathConnection, +code: U32, message: String) -> IO(T):
  do IO<T>:
    Quic.close_multipath(conn)
    IO.die(T,code,message)

def ok(-T: Type, pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,T>)
    -> IO(Quic.MultipathConnection & T):
  match pair:
    case (conn,Done{value}):
      IO.pure(Quic.MultipathConnection & T,(conn,value))
    case (conn,Fail{(code,message)}):
      reject(Quic.MultipathConnection & T,conn,code,message)

def stepped(pair: Quic.MultipathConnection & U32) -> Quic.MultipathConnection:
  (conn,_) = pair
  conn

def step(conn: Quic.MultipathConnection) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.step_multipath(conn)
    pair : Quic.MultipathConnection & U32 <- ok(U32,result)
    return stepped(pair)

def probe_result(pair: Quic.MultipathConnection & Maybe<&1,U32>,
    retry: Quic.MultipathConnection -> IO(Quic.MultipathConnection & U32))
    -> IO(Quic.MultipathConnection & U32):
  match pair:
    case (conn,Some{path}):
      IO.pure(Quic.MultipathConnection & U32,(conn,path))
    case (conn,None{}):
      do IO<Quic.MultipathConnection & U32>:
        IO.sleep(1)
        retry(conn)

def probe(fuel: Nat, conn: Quic.MultipathConnection, +host: String, +port: U32)
    -> IO(Quic.MultipathConnection & U32):
  match fuel:
    case 0n:
      reject(Quic.MultipathConnection & U32,conn,1,"could not open a second QUIC path")
    case 1n+left:
      do IO<Quic.MultipathConnection & U32>:
        active : Quic.MultipathConnection <- step(conn)
        value : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <-
          Quic.probe_multipath(active,host,0,host,port)
        path : Quic.MultipathConnection & Maybe<&1,U32> <- ok(Maybe<&1,U32>,value)
        probe_result(path,next => probe(left,next,host,port))

def path_result(pair: Quic.MultipathConnection & U32,
    retry: Quic.MultipathConnection -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  match pair:
    case (conn,1):
      IO.pure(Quic.MultipathConnection,conn)
    case (conn,0):
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        retry(conn)
    case (conn,_):
      reject(Quic.MultipathConnection,conn,1,"candidate QUIC path became unavailable")

def wait_path(fuel: Nat, conn: Quic.MultipathConnection, +path: U32) -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      reject(Quic.MultipathConnection,conn,1,"QUIC path validation timed out")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        active : Quic.MultipathConnection <- step(conn)
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.multipath_status(active,path)
        state : Quic.MultipathConnection & U32 <- ok(U32,result)
        path_result(state,next => wait_path(left,next,path))

def open_result(pair: Quic.MultipathConnection & Maybe<&1,U32>) -> IO(Quic.MultipathConnection & U32):
  match pair:
    case (conn,Some{stream}):
      IO.pure(Quic.MultipathConnection & U32,(conn,stream))
    case (conn,None{}):
      reject(Quic.MultipathConnection & U32,conn,1,"could not open a QUIC stream")

def open(conn: Quic.MultipathConnection) -> IO(Quic.MultipathConnection & U32):
  do IO<Quic.MultipathConnection & U32>:
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <- Quic.open_multipath_stream(conn,0)
    value : Quic.MultipathConnection & Maybe<&1,U32> <- ok(Maybe<&1,U32>,result)
    open_result(value)

def write_result(pair: Quic.MultipathConnection & U32, stream: U32) -> IO(Quic.MultipathConnection & U32):
  match pair:
    case (conn,1):
      IO.pure(Quic.MultipathConnection & U32,(conn,stream))
    case (conn,_):
      reject(Quic.MultipathConnection & U32,conn,1,"could not queue QUIC stream bytes")

def write_assigned(ready: Quic.MultipathConnection & Unit, +stream: U32, byte: U32)
    -> IO(Quic.MultipathConnection & U32):
  (conn,_) = ready
  do IO<Quic.MultipathConnection & U32>:
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <-
      Quic.write_multipath_stream(conn,stream,[byte],1)
    outcome : Quic.MultipathConnection & U32 <- ok(U32,result)
    write_result(outcome,stream)

def assign(cleared: Quic.MultipathConnection & Unit, +stream: U32, path: U32, byte: U32)
    -> IO(Quic.MultipathConnection & U32):
  (conn,_) = cleared
  do IO<Quic.MultipathConnection & U32>:
    assigned : Quic.MultipathConnection & Result<&1,&1,U32 & String,Unit> <- Quic.assign_stream_path(conn,stream,path)
    ready : Quic.MultipathConnection & Unit <- ok(Unit,assigned)
    write_assigned(ready,stream,byte)

def send(opened: Quic.MultipathConnection & U32, path: U32, byte: U32) -> IO(Quic.MultipathConnection & U32):
  (conn,+stream) = opened
  do IO<Quic.MultipathConnection & U32>:
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,Unit> <- Quic.clear_stream_path(conn,stream)
    cleared : Quic.MultipathConnection & Unit <- ok(Unit,result)
    assign(cleared,stream,path,byte)

def check_byte(conn: Quic.MultipathConnection, equal: Bool,
    retry: Quic.MultipathConnection -> Bool -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  match equal:
    case True{}:
      retry(conn,True{})
    case False{}:
      reject(Quic.MultipathConnection,conn,1,"unexpected QUIC stream byte")

def receive_value(pair: Quic.MultipathConnection & Quic.MultipathRead, expected: U32, seen: Bool,
    retry: Quic.MultipathConnection -> Bool -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  match pair expected seen:
    case (conn,Quic.MultipathReadPending{}) _ seen:
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        retry(conn,seen)
    case (conn,Quic.MultipathReadBytes{[byte]}) expected False{}:
      check_byte(conn,U32.is_eq(byte,expected),retry)
    case (conn,Quic.MultipathReadFin{}) _ True{}:
      IO.pure(Quic.MultipathConnection,conn)
    case (conn,_) _ _:
      reject(Quic.MultipathConnection,conn,1,"unexpected QUIC stream reply")

def receive(fuel: Nat, conn: Quic.MultipathConnection, +stream: U32, +byte: U32, seen: Bool)
    -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      reject(Quic.MultipathConnection,conn,1,"QUIC stream reply timed out")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        active : Quic.MultipathConnection <- step(conn)
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,Quic.MultipathRead> <-
          Quic.read_multipath_stream(active,stream,1)
        value : Quic.MultipathConnection & Quic.MultipathRead <- ok(Quic.MultipathRead,result)
        receive_value(value,byte,seen,next => flag => receive(left,next,stream,byte,flag))

def assert_live(pair: Quic.MultipathConnection & U32) -> IO(Unit):
  match pair:
    case (conn,1):
      do IO<Unit>:
        Quic.close_multipath(conn)
        IO.print("PASS Bend exchanged two streams across simultaneous paths")
    case (conn,_):
      reject(Unit,conn,1,"alternate QUIC path disappeared")

def released(outcome: Quic.MultipathConnection & Unit) -> Quic.MultipathConnection:
  (conn,_) = outcome
  conn

def release(conn: Quic.MultipathConnection, stream: U32) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,Unit> <- Quic.drop_multipath_stream(conn,stream)
    outcome : Quic.MultipathConnection & Unit <- ok(Unit,result)
    return released(outcome)

def second(sent: Quic.MultipathConnection & U32, path: U32, +first: U32) -> IO(Unit):
  (conn,+stream) = sent
  do IO<Unit>:
    original : Quic.MultipathConnection <- receive(3000n,conn,first,11,False{})
    alternate : Quic.MultipathConnection <- receive(3000n,original,stream,22,False{})
    one : Quic.MultipathConnection <- release(alternate,first)
    empty : Quic.MultipathConnection <- release(one,stream)
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.multipath_status(empty,path)
    state : Quic.MultipathConnection & U32 <- ok(U32,result)
    assert_live(state)

def send_second(sent: Quic.MultipathConnection & U32, +path: U32) -> IO(Unit):
  (conn,first) = sent
  do IO<Unit>:
    opened : Quic.MultipathConnection & U32 <- open(conn)
    sent_b : Quic.MultipathConnection & U32 <- send(opened,path,22)
    second(sent_b,path,first)

def run_paths(candidate: Quic.MultipathConnection & U32) -> IO(Unit):
  (conn,+path) = candidate
  do IO<Unit>:
    ready : Quic.MultipathConnection <- wait_path(3000n,conn,path)
    opened : Quic.MultipathConnection & U32 <- open(ready)
    sent : Quic.MultipathConnection & U32 <- send(opened,0,11)
    send_second(sent,path)

def fixture_key(wrong: U32) -> List<&2,U32>:
  match wrong:
    case 0:
      [25,127,107,35,225,108,133,50,198,171,200,56,250,205,94,167,137,190,12,118,178,146,3,52,3,155,250,139,61,54,141,97]
    case _:
      List.replicate(U32,32n,0)

def run_probe(conn: Quic.MultipathConnection, host: String, port: U32) -> IO(Unit):
  do IO<Unit>:
    candidate : Quic.MultipathConnection & U32 <- probe(3000n,conn,host,port)
    run_paths(candidate)

def dial_result(result: Quic.ConnectResult(), wrong: U32, host: String, port: U32) -> IO(Unit):
  match result wrong:
    case Done{conn} 0:
      run_probe(conn,host,port)
    case Fail{(13,_)} 1:
      IO.print("PASS Bend rejected the wrong Iroh endpoint pin")
    case Fail{(code,message)} _:
      IO.die(Unit,code,message)
    case Done{conn} _:
      reject(Unit,conn,1,"wrong Iroh endpoint pin was accepted")

def dial(+host: String, +port: U32, +wrong: U32) -> IO(Unit):
  do IO<Unit>:
    result : Quic.ConnectResult() <-
      Quic.connect_multipath(host,port,List.replicate(U32,32n,73),fixture_key(wrong),"iroh-bend/compat/1",3000n)
    dial_result(result,wrong,host,port)

def parse(host: String, port: Maybe<&2,U32>, wrong: U32) -> IO(Unit):
  match port:
    case Some{number}:
      dial(host,number,wrong)
    case None{}:
      IO.die(Unit,2,"expected a numeric port")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{host,Con{port,Nil{}}}}:
      parse(host,U32.read(port),0)
    case Con{_,Con{host,Con{port,Con{_,Nil{}}}}}:
      parse(host,U32.read(port),1)
    case _:
      IO.die(Unit,2,"expected a host and port")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
