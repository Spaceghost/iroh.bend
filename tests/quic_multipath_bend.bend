import Base
import ../src/quic_multipath.bend as Quic
import ../src/quic_nat.bend as NatWire
import ../src/quic_nat_state.bend as NatState
import ../src/quic_nat_send.bend as NatSend
import ../src/quic_multipath_nat.bend as NatProbe

def binary_alpn() -> List<&2,U32>:
  Con{0,Con{255,Con{10,List.replicate(U32,252n,128)}}}

def text_alpn() -> List<&2,U32>:
  [105,114,111,104,45,98,101,110,100,47,99,111,109,112,97,116,47,49]

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
        IO.print("PASS Bend exchanged datagrams and two streams on one multipath connection")
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

def same_bytes(actual: List<&2,U32>, expected: List<&2,U32>) -> Bool:
  match actual expected:
    case Nil{} Nil{}:
      True{}
    case Con{a,rest} Con{b,tail}:
      U32.is_eq(a,b) && same_bytes(rest,tail)
    case _ _:
      False{}

def checked_datagram(conn: Quic.MultipathConnection, valid: Bool) -> IO(Quic.MultipathConnection):
  match valid:
    case True{}:
      IO.pure(Quic.MultipathConnection,conn)
    case False{}:
      reject(Quic.MultipathConnection,conn,1,"unexpected multipath datagram bytes")

def received_datagram(value: Quic.MultipathConnection & Maybe<&1,List<&2,U32>>, expected: List<&2,U32>,
    retry: Quic.MultipathConnection -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  match value:
    case (conn,Some{bytes}):
      checked_datagram(conn,same_bytes(bytes,expected))
    case (conn,None{}):
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        retry(conn)

def read_datagram(fuel: Nat, conn: Quic.MultipathConnection, +expected: List<&2,U32>) -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      reject(Quic.MultipathConnection,conn,1,"multipath datagram timed out")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        active : Quic.MultipathConnection <- step(conn)
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>> <-
          Quic.read_multipath_datagram(active)
        value : Quic.MultipathConnection & Maybe<&1,List<&2,U32>> <- ok(Maybe<&1,List<&2,U32>>,result)
        received_datagram(value,expected,next => read_datagram(left,next,expected))

def written_datagram(value: Quic.MultipathConnection & U32,
    retry: Quic.MultipathConnection -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  match value:
    case (conn,1):
      IO.pure(Quic.MultipathConnection,conn)
    case (conn,_):
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        retry(conn)

def send_datagram(fuel: Nat, conn: Quic.MultipathConnection, +bytes: List<&2,U32>) -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      reject(Quic.MultipathConnection,conn,1,"multipath datagram queue remained full")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        active : Quic.MultipathConnection <- step(conn)
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.write_multipath_datagram(active,bytes)
        value : Quic.MultipathConnection & U32 <- ok(U32,result)
        written_datagram(value,next => send_datagram(left,next,bytes))

def oversize_result(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>)
    -> IO(Quic.MultipathConnection):
  match pair:
    case (conn,Fail{(90,_)}):
      IO.pure(Quic.MultipathConnection,conn)
    case (conn,_):
      reject(Quic.MultipathConnection,conn,1,"oversized multipath datagram was accepted")

def test_limit(pair: Quic.MultipathConnection & U32) -> IO(Quic.MultipathConnection):
  match pair:
    case (conn,0):
      reject(Quic.MultipathConnection,conn,1,"multipath datagrams were not negotiated")
    case (conn,limit):
      do IO<Quic.MultipathConnection>:
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <-
          Quic.write_multipath_datagram(conn,List.replicate(U32,Nat.add(U32.to_nat(limit),1n),0))
        oversize_result(result)

def datagram_exchange(conn: Quic.MultipathConnection) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.multipath_datagram_limit(conn)
    limit : Quic.MultipathConnection & U32 <- ok(U32,result)
    tested : Quic.MultipathConnection <- test_limit(limit)
    sent : Quic.MultipathConnection <- send_datagram(3000n,tested,[0,128,255])
    reply : Quic.MultipathConnection <- read_datagram(3000n,sent,[255,128,0])
    empty : Quic.MultipathConnection <- send_datagram(3000n,reply,[])
    read_datagram(3000n,empty,[])

def run_paths(candidate: Quic.MultipathConnection & U32) -> IO(Unit):
  (conn,+path) = candidate
  do IO<Unit>:
    ready : Quic.MultipathConnection <- wait_path(3000n,conn,path)
    datagrams : Quic.MultipathConnection <- datagram_exchange(ready)
    opened : Quic.MultipathConnection & U32 <- open(datagrams)
    sent : Quic.MultipathConnection & U32 <- send(opened,0,11)
    send_second(sent,path)

def fixture_key(mode: U32) -> List<&2,U32>:
  match mode:
    case 1:
      List.replicate(U32,32n,0)
    case _:
      [25,127,107,35,225,108,133,50,198,171,200,56,250,205,94,167,137,190,12,118,178,146,3,52,3,155,250,139,61,54,141,97]

def run_probe(conn: Quic.MultipathConnection, host: String, port: U32) -> IO(Unit):
  do IO<Unit>:
    candidate : Quic.MultipathConnection & U32 <- probe(3000n,conn,host,port)
    run_paths(candidate)

def checked_alpn(conn: Quic.MultipathConnection, equal: Bool) -> IO(Quic.MultipathConnection):
  match equal:
    case True{}:
      IO.pure(Quic.MultipathConnection,conn)
    case False{}:
      reject(Quic.MultipathConnection,conn,1,"negotiated the wrong ALPN")

def compare_alpn(selected: Quic.MultipathConnection & List<&2,U32>, expected: List<&2,U32>)
    -> IO(Quic.MultipathConnection):
  (conn,actual) = selected
  checked_alpn(conn,same_bytes(actual,expected))

def require_alpn(conn: Quic.MultipathConnection, expected: List<&2,U32>) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>> <-
      Quic.negotiated_multipath_alpn(conn)
    selected : Quic.MultipathConnection & List<&2,U32> <- ok(List<&2,U32>,result)
    compare_alpn(selected,expected)

def dial_multiple(+host: String, +port: U32) -> IO(Unit):
  do IO<Unit>:
    conn : Quic.MultipathConnection <- IO.try(Quic.MultipathConnection,
      Quic.connect_multipath_alpns(host,port,List.replicate(U32,32n,73),fixture_key(0),
        [text_alpn(),binary_alpn()],3000n))
    selected : Quic.MultipathConnection <- require_alpn(conn,binary_alpn())
    IO.print("PASS Bend read Iroh's preferred binary ALPN")
    run_probe(selected,host,port)

def parse_multiple(host: String, port: Maybe<&2,U32>) -> IO(Unit):
  match port:
    case Some{number}:
      dial_multiple(host,number)
    case None{}:
      IO.die(Unit,2,"expected a numeric port")

def validate_nat_limit(conn: Quic.MultipathConnection, limit: NatWire.ParameterResult)
    -> IO(Quic.MultipathConnection):
  match limit:
    case NatWire.ParameterLimit{32}:
      do IO<Quic.MultipathConnection>:
        IO.print("PASS Bend read Iroh's authenticated NAT traversal limit")
        return conn
    case _:
      reject(Quic.MultipathConnection,conn,1,"expected Iroh's default NAT traversal limit of 32")

def validate_peer_parameters(pair: Quic.MultipathConnection & List<&2,U32>)
    -> IO(Quic.MultipathConnection):
  (conn,parameters) = pair
  validate_nat_limit(conn,NatWire.read_parameters(parameters))

def read_peer_parameters(conn: Quic.MultipathConnection) -> IO(Quic.MultipathConnection & List<&2,U32>):
  do IO<Quic.MultipathConnection & List<&2,U32>>:
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>> <-
      Quic.peer_multipath_parameters(conn)
    ok(List<&2,U32>,result)

def require_nat_limit(conn: Quic.MultipathConnection) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    pair : Quic.MultipathConnection & List<&2,U32> <- read_peer_parameters(conn)
    validate_peer_parameters(pair)

def validate_offered_limit(conn: Quic.MultipathConnection, parsed: NatWire.ParameterResult)
    -> IO(Quic.MultipathConnection):
  match parsed:
    case NatWire.ParameterLimit{64}:
      IO.pure(Quic.MultipathConnection,conn)
    case _:
      reject(Quic.MultipathConnection,conn,1,"expected Bend listener's NAT traversal limit of 64")

def verify_offered_parameters(pair: Quic.MultipathConnection & List<&2,U32>)
    -> IO(Quic.MultipathConnection):
  (conn,parameters) = pair
  validate_offered_limit(conn,NatWire.read_parameters(parameters))

def require_bend_nat_offer(conn: Quic.MultipathConnection) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    pair : Quic.MultipathConnection & List<&2,U32> <- read_peer_parameters(conn)
    next : Quic.MultipathConnection <- verify_offered_parameters(pair)
    IO.print("PASS Bend read the listener's authenticated NAT traversal limit of 64")
    return next

def report_withdrawal(conn: Quic.MultipathConnection, correct: Bool) -> IO(Quic.MultipathConnection):
  match correct:
    case True{}:
      do IO<Quic.MultipathConnection>:
        IO.print("PASS Bend applied live ADD_ADDRESS and REMOVE_ADDRESS")
        return conn
    case False{}:
      reject(Quic.MultipathConnection,conn,1,"Iroh NAT withdrawal returned the wrong candidate port")

def punched_path_ready(pair: Quic.MultipathConnection & U32) -> IO(Quic.MultipathConnection):
  (conn,path) = pair
  do IO<Quic.MultipathConnection>:
    ready : Quic.MultipathConnection <- wait_path(5000n,conn,path)
    IO.print("PASS Bend validated the new QUIC path on the punched UDP socket")
    return ready

def open_nat_result(pair: Quic.MultipathConnection & Maybe<&1,U32>,
    retry: Quic.MultipathConnection -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  match pair:
    case (conn,Some{path}):
      punched_path_ready((conn,path))
    case (conn,None{}):
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        retry(conn)

def open_nat_path(fuel: Nat, conn: Quic.MultipathConnection, +target: NatState.Candidate)
    -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      reject(Quic.MultipathConnection,conn,1,"could not open the punched QUIC path")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        active : Quic.MultipathConnection <- step(conn)
        opened : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <-
          NatProbe.open_path(active,target)
        pair : Quic.MultipathConnection & Maybe<&1,U32> <- ok(Maybe<&1,U32>,opened)
        open_nat_result(pair,next => open_nat_path(left,next,target))

def confirm_nat_path(conn: Quic.MultipathConnection, target: NatState.Candidate, open: Bool)
    -> IO(Quic.MultipathConnection):
  match open:
    case True{}:
      open_nat_path(5000n,conn,target)
    case False{}:
      IO.pure(Quic.MultipathConnection,conn)

def finish_nat_probe(result: Quic.MultipathConnection & NatProbe.Progress,
    target: NatState.Candidate, open: Bool, retry: Quic.MultipathConnection -> NatProbe.Probe -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  match result:
    case (conn,NatProbe.Answered{port}):
      do IO<Quic.MultipathConnection>:
        IO.print(String.append("PASS Bend dialer verified Iroh's PATH_RESPONSE from port ",U32.show(port)))
        confirm_nat_path(conn,target,open)
    case (conn,NatProbe.Pending{probe}):
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        retry(conn,probe)
    case (conn,NatProbe.Failed{code,message}):
      reject(Quic.MultipathConnection,conn,code,message)
    case (conn,NatProbe.TimedOut{}):
      reject(Quic.MultipathConnection,conn,1,"Bend dialer NAT probe expired")

def wait_nat_probe(fuel: Nat, conn: Quic.MultipathConnection, probe: NatProbe.Probe,
    +target: NatState.Candidate, +open: Bool) -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      reject(Quic.MultipathConnection,conn,1,"Iroh did not answer the Bend dialer's NAT probe")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        active : Quic.MultipathConnection <- step(conn)
        progress : Quic.MultipathConnection & NatProbe.Progress <- NatProbe.poll(active,probe)
        finish_nat_probe(progress,target,open,next => current => wait_nat_probe(left,next,current,target,open))

def reach_progress(pair: Quic.MultipathConnection & U32,
    ready: Quic.MultipathConnection -> IO(Quic.MultipathConnection),
    retry: Quic.MultipathConnection -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  match pair:
    case (conn,1):
      ready(conn)
    case (conn,_):
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        retry(conn)

def rejected_preflight(result: Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>)
    -> IO(Quic.MultipathConnection):
  match result:
    case (conn,Fail{(13,_)}):
      IO.pure(Quic.MultipathConnection,conn)
    case (conn,_):
      reject(Quic.MultipathConnection,conn,1,"opened a NAT candidate without a matching probe response")

def check_unverified_candidate(conn: Quic.MultipathConnection, target: NatState.Candidate, validate: Bool)
    -> IO(Quic.MultipathConnection):
  match validate:
    case True{}:
      do IO<Quic.MultipathConnection>:
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <- NatProbe.open_path(conn,target)
        rejected_preflight(result)
    case False{}:
      IO.pure(Quic.MultipathConnection,conn)

def send_reach_out(fuel: Nat, conn: Quic.MultipathConnection, +frame: NatWire.Frame, +target: NatState.Candidate, +open: Bool)
    -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      reject(Quic.MultipathConnection,conn,1,"Iroh did not acknowledge Bend's REACH_OUT")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        active : Quic.MultipathConnection <- step(conn)
        sent : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- NatProbe.send_address(active,frame)
        progress : Quic.MultipathConnection & U32 <- ok(U32,sent)
        reach_progress(progress,ready =>
          do IO<Quic.MultipathConnection>:
            IO.print("PASS Iroh acknowledged the Bend dialer's REACH_OUT")
            unverified : Quic.MultipathConnection <- check_unverified_candidate(ready,target,open)
            probe : NatProbe.Probe <- NatProbe.start(target,333000)
            wait_nat_probe(5000n,unverified,probe,target,open),
          retry => send_reach_out(left,retry,frame,target,open))

def send_nat_round(conn: Quic.MultipathConnection, attempt: NatSend.RoundResult, open: Bool) -> IO(Quic.MultipathConnection):
  match attempt:
    case NatSend.Round{_,NatSend.RoundStarted{_,[frame],[target]}}:
      send_reach_out(4000n,conn,frame,target,open)
    case _:
      reject(Quic.MultipathConnection,conn,1,"expected a local and remote candidate for NAT traversal")

def is_ipv6(candidate: NatState.Candidate) -> Bool:
  match candidate:
    case NatState.Socket{NatWire.IPv6{_},_}:
      True{}
    case _:
      False{}

def begin_nat_round(conn: Quic.MultipathConnection, local: NatSend.Change, peer: NatState.PeerState, ipv6: Bool, open: Bool)
    -> IO(Quic.MultipathConnection):
  match local:
    case NatSend.Changed{state,NatSend.Updated{}}:
      send_nat_round(conn,NatSend.begin(state,peer,ipv6),open)
    case _:
      reject(Quic.MultipathConnection,conn,1,"could not register the dialer's local NAT candidate")

def local_candidate_ready(pair: Quic.MultipathConnection & NatState.Candidate, peer: NatState.PeerState, open: Bool)
    -> IO(Quic.MultipathConnection):
  (conn,+candidate) = pair
  local = NatSend.start(NatState.Client{},True{},Some{64},Some{32})
  begin_nat_round(conn,NatSend.add(local,candidate),peer,is_ipv6(candidate),open)

def start_nat_round(conn: Quic.MultipathConnection, peer: NatState.PeerState, open: Bool) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    local : Quic.MultipathConnection & Result<&1,&1,U32 & String,NatState.Candidate> <- NatProbe.local_candidate(conn)
    pair : Quic.MultipathConnection & NatState.Candidate <- ok(NatState.Candidate,local)
    local_candidate_ready(pair,peer,open)

def candidate_received(conn: Quic.MultipathConnection, change: NatState.Transition, port: U32, mode: U32,
    next: Quic.MultipathConnection -> NatState.PeerState -> IO(Quic.MultipathConnection))
    -> IO(Quic.MultipathConnection):
  match change mode:
    case NatState.Received{state,NatState.AddressAdded{_}} 4:
      do IO<Quic.MultipathConnection>:
        IO.print("PASS Bend accepted an authenticated Iroh ADD_ADDRESS")
        start_nat_round(conn,state,False{})
    case NatState.Received{state,NatState.AddressAdded{_}} 7:
      start_nat_round(conn,state,True{})
    case NatState.Received{_,NatState.AddressRemoved{NatState.Socket{_,removed}}} 6:
      report_withdrawal(conn,U32.is_eq(removed,port))
    case NatState.Received{state,NatState.AddressAdded{_}} 6:
      next(conn,state)
    case NatState.Received{state,NatState.Ignored{}} _:
      next(conn,state)
    case _ _:
      reject(Quic.MultipathConnection,conn,1,"unexpected NAT address update")

def apply_nat_frame(conn: Quic.MultipathConnection, result: NatWire.DecodeResult, state: NatState.PeerState,
    port: U32, mode: U32, next: Quic.MultipathConnection -> NatState.PeerState -> IO(Quic.MultipathConnection))
    -> IO(Quic.MultipathConnection):
  match result:
    case NatWire.Decoded{frame,Nil{}}:
      candidate_received(conn,NatState.receive(state,frame),port,mode,next)
    case _:
      reject(Quic.MultipathConnection,conn,1,"invalid authenticated NAT address update")

def handle_candidate(result: Quic.MultipathConnection & Maybe<&1,List<&2,U32>>, state: NatState.PeerState,
    port: U32, mode: U32, next: Quic.MultipathConnection -> NatState.PeerState -> IO(Quic.MultipathConnection))
    -> IO(Quic.MultipathConnection):
  match result:
    case (conn,Some{wire}):
      apply_nat_frame(conn,NatWire.decode(wire),state,port,mode,next)
    case (conn,None{}):
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        next(conn,state)

def wait_address(fuel: Nat, conn: Quic.MultipathConnection, state: NatState.PeerState, +port: U32, +mode: U32)
    -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      reject(Quic.MultipathConnection,conn,1,"did not receive the expected NAT address update")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        ready : Quic.MultipathConnection <- step(conn)
        incoming : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>> <-
          Quic.read_multipath_nat_frame(ready)
        pair : Quic.MultipathConnection & Maybe<&1,List<&2,U32>> <- ok(Maybe<&1,List<&2,U32>>,incoming)
        handle_candidate(pair,state,port,mode,next => updated =>
          wait_address(left,next,updated,port,mode))

def run_punched_path(conn: Quic.MultipathConnection) -> IO(Unit):
  do IO<Unit>:
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <- Quic.next_multipath_path(conn,0)
    probe : Quic.MultipathConnection & Maybe<&1,U32> <- ok(Maybe<&1,U32>,result)
    path : Quic.MultipathConnection & U32 <- open_result(probe)
    run_paths(path)

def dial_result(result: Quic.ConnectResult(), mode: U32, host: String, +port: U32) -> IO(Unit):
  match result mode:
    case Done{conn} 2:
      do IO<Unit>:
        ready : Quic.MultipathConnection <- require_nat_limit(conn)
        run_probe(ready,host,port)
    case Done{conn} 3:
      do IO<Unit>:
        ready : Quic.MultipathConnection <- require_bend_nat_offer(conn)
        run_probe(ready,host,port)
    case Done{conn} 4:
      do IO<Unit>:
        active : Quic.MultipathConnection <- wait_address(5000n,conn,
          NatState.start(NatState.Client{},True{},Some{64},Some{32}),port,4)
        run_probe(active,host,port)
    case Done{conn} 7:
      do IO<Unit>:
        active : Quic.MultipathConnection <- wait_address(5000n,conn,
          NatState.start(NatState.Client{},True{},Some{64},Some{32}),port,7)
        run_punched_path(active)
    case Done{conn} 6:
      do IO<Unit>:
        active : Quic.MultipathConnection <- wait_address(5000n,conn,
          NatState.start(NatState.Client{},True{},Some{64},Some{64}),port,6)
        run_probe(active,host,port)
    case Done{conn} 0:
      run_probe(conn,host,port)
    case Fail{(13,_)} 1:
      IO.print("PASS Bend rejected the wrong Iroh endpoint pin")
    case Fail{(code,message)} _:
      IO.die(Unit,code,message)
    case Done{conn} _:
      reject(Unit,conn,1,"wrong Iroh endpoint pin was accepted")

def open_client(host: String, port: U32, key: List<&2,U32>, offer: Bool) -> IO(Quic.ConnectResult()):
  match offer:
    case True{}:
      Quic.connect_multipath_with_nat_limit(host,port,List.replicate(U32,32n,73),key,"iroh-bend/compat/1",64,3000n)
    case False{}:
      Quic.connect_multipath(host,port,List.replicate(U32,32n,73),key,"iroh-bend/compat/1",3000n)

def dial(+host: String, +port: U32, +mode: U32) -> IO(Unit):
  do IO<Unit>:
    result : Quic.ConnectResult() <- open_client(host,port,fixture_key(mode),U32.is_eq(mode,4) || U32.is_eq(mode,6) || U32.is_eq(mode,7))
    dial_result(result,mode,host,port)

def parse(host: String, port: Maybe<&2,U32>, mode: U32) -> IO(Unit):
  match port:
    case Some{number}:
      dial(host,number,mode)
    case None{}:
      IO.die(Unit,2,"expected a numeric port")

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,host,port,"multiple"]:
      parse_multiple(host,U32.read(port))
    case [_,host,port,"iroh-parameters"]:
      parse(host,U32.read(port),2)
    case [_,host,port,"bend-nat-offer"]:
      parse(host,U32.read(port),3)
    case [_,host,port,"iroh-nat-dial"]:
      parse(host,U32.read(port),4)
    case [_,host,port,"iroh-nat-punch"]:
      parse(host,U32.read(port),7)
    case [_,host,port,"bend-nat-dial"]:
      parse(host,U32.read(port),6)
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
