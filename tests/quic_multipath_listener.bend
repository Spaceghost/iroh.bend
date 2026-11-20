import Base
import ../src/quic_multipath.bend as Quic
import ../src/quic_nat.bend as NatWire
import ../src/quic_nat_state.bend as NatState
import ../src/quic_nat_send.bend as NatSend
import ../src/quic_multipath_nat.bend as Probes
import ./quic_multipath_bend.bend as Fixture

def accepted_result(pair: Quic.MultipathListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>>,
    retry: Quic.MultipathListener -> IO(Quic.MultipathListener & Quic.MultipathConnection))
    -> IO(Quic.MultipathListener & Quic.MultipathConnection):
  match pair:
    case (listener,Done{Some{conn}}):
      IO.pure(Quic.MultipathListener & Quic.MultipathConnection,(listener,conn))
    case (listener,Done{None{}}):
      do IO<Quic.MultipathListener & Quic.MultipathConnection>:
        IO.sleep(1)
        retry(listener)
    case (listener,Fail{(code,message)}):
      do IO<Quic.MultipathListener & Quic.MultipathConnection>:
        Quic.close_multipath_listener(listener)
        IO.die(Quic.MultipathListener & Quic.MultipathConnection,code,message)

def accept(fuel: Nat, listener: Quic.MultipathListener) -> IO(Quic.MultipathListener & Quic.MultipathConnection):
  match fuel:
    case 0n:
      do IO<Quic.MultipathListener & Quic.MultipathConnection>:
        Quic.close_multipath_listener(listener)
        IO.die(Quic.MultipathListener & Quic.MultipathConnection,1,"multipath accept timed out")
    case 1n+left:
      do IO<Quic.MultipathListener & Quic.MultipathConnection>:
        result : Quic.MultipathListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>> <-
          Quic.accept_multipath(listener)
        accepted_result(result,next => accept(left,next))

def incoming(fuel: Nat, conn: Quic.MultipathConnection, +dir: U32) -> IO(Quic.MultipathConnection & U32):
  match fuel:
    case 0n:
      Fixture.reject(Quic.MultipathConnection & U32,conn,1,"incoming multipath stream timed out")
    case 1n+left:
      do IO<Quic.MultipathConnection & U32>:
        active : Quic.MultipathConnection <- Fixture.step(conn)
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <-
          Quic.accept_multipath_stream(active,dir)
        progress : Quic.MultipathConnection & Maybe<&1,U32> <- Fixture.ok(Maybe<&1,U32>,result)
        Fixture.probe_result(progress,next => incoming(left,next,dir))

def read_uni(opened: Quic.MultipathConnection & U32, byte: U32) -> IO(Quic.MultipathConnection):
  (conn,+stream) = opened
  do IO<Quic.MultipathConnection>:
    read : Quic.MultipathConnection <- Fixture.receive(4000n,conn,stream,byte,False{})
    Fixture.release(read,stream)

def receive_uni(conn: Quic.MultipathConnection, byte: U32) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    opened : Quic.MultipathConnection & U32 <- incoming(4000n,conn,1)
    read_uni(opened,byte)

def echo(opened: Quic.MultipathConnection & U32, path: U32, +byte: U32) -> IO(Quic.MultipathConnection):
  (conn,+stream) = opened
  do IO<Quic.MultipathConnection>:
    read : Quic.MultipathConnection <- Fixture.receive(4000n,conn,stream,byte,False{})
    sent : Quic.MultipathConnection & U32 <- Fixture.send((read,stream),path,byte)
    return Fixture.stepped(sent)

def echo_pair(conn: Quic.MultipathConnection, first: U32, second: U32, path: U32)
    -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    a : Quic.MultipathConnection & U32 <- incoming(4000n,conn,0)
    echoed_a : Quic.MultipathConnection <- echo(a,0,first)
    b : Quic.MultipathConnection & U32 <- incoming(4000n,echoed_a,0)
    echo(b,path,second)

def datagram_echo(conn: Quic.MultipathConnection) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    binary : Quic.MultipathConnection <- Fixture.read_datagram(4000n,conn,[0,128,255])
    sent : Quic.MultipathConnection <- Fixture.send_datagram(4000n,binary,[255,128,0])
    empty : Quic.MultipathConnection <- Fixture.read_datagram(4000n,sent,[])
    Fixture.send_datagram(4000n,empty,[])

def exchange(conn: Quic.MultipathConnection, uni: U32, first: U32, second: U32) -> IO(Unit):
  do IO<Unit>:
    datagrams : Quic.MultipathConnection <- datagram_echo(conn)
    primed : Quic.MultipathConnection <- receive_uni(datagrams,uni)
    echoed : Quic.MultipathConnection <- echo_pair(primed,first,second,0)
    confirmed : Quic.MultipathConnection <- receive_uni(echoed,77)
    Quic.close_multipath(confirmed)

def wait_path(fuel: Nat, conn: Quic.MultipathConnection) -> IO(Quic.MultipathConnection & U32):
  match fuel:
    case 0n:
      Fixture.reject(Quic.MultipathConnection & U32,conn,1,"peer did not open a second path")
    case 1n+left:
      do IO<Quic.MultipathConnection & U32>:
        active : Quic.MultipathConnection <- Fixture.step(conn)
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <-
          Quic.next_multipath_path(active,0)
        paths : Quic.MultipathConnection & Maybe<&1,U32> <- Fixture.ok(Maybe<&1,U32>,result)
        Fixture.probe_result(paths,next => wait_path(left,next))

def waited(result: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>,
    resume: Quic.MultipathConnection -> IO(Unit)) -> IO(Unit):
  match result:
    case (conn,Done{_}):
      do IO<Unit>:
        IO.sleep(1)
        resume(conn)
    case (conn,Fail{(104,_)}):
      do IO<Unit>:
        Quic.close_multipath(conn)
        IO.print("PASS Bend listener accepted and used the dialer's second path")
    case (conn,Fail{(code,message)}):
      Fixture.reject(Unit,conn,code,message)

def wait_close(fuel: Nat, conn: Quic.MultipathConnection) -> IO(Unit):
  match fuel:
    case 0n:
      Fixture.reject(Unit,conn,1,"multipath peer did not close")
    case 1n+left:
      do IO<Unit>:
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.step_multipath(conn)
        waited(result,next => wait_close(left,next))

def echo_affine(candidate: Quic.MultipathConnection & U32) -> IO(Unit):
  (conn,path) = candidate
  do IO<Unit>:
    datagrams : Quic.MultipathConnection <- datagram_echo(conn)
    echoed : Quic.MultipathConnection <- echo_pair(datagrams,11,22,path)
    wait_close(5000n,echoed)

def serve_affinity(first: Quic.MultipathListener & Quic.MultipathConnection) -> IO(Unit):
  (listener,conn) = first
  do IO<Unit>:
    Quic.close_multipath_listener(listener)
    candidate : Quic.MultipathConnection & U32 <- wait_path(5000n,conn)
    echo_affine(candidate)

def check_selection(conn: Quic.MultipathConnection, expected: List<&2,U32>, mode: U32)
    -> IO(Quic.MultipathConnection):
  match mode:
    case 3:
      Fixture.require_alpn(conn,expected)
    case _:
      IO.pure(Quic.MultipathConnection,conn)

def check_distinct(first: Quic.MultipathConnection, second: Quic.MultipathConnection, equal: Bool)
    -> IO(Quic.MultipathConnection & Quic.MultipathConnection):
  match equal:
    case False{}:
      IO.pure(Quic.MultipathConnection & Quic.MultipathConnection,(first,second))
    case True{}:
      do IO<Quic.MultipathConnection & Quic.MultipathConnection>:
        Quic.close_multipath(first)
        Fixture.reject(Quic.MultipathConnection & Quic.MultipathConnection,second,1,
          "distinct connections returned the same transport parameter bytes")

def validate_both(a: Quic.MultipathConnection & List<&2,U32>, b: Quic.MultipathConnection & List<&2,U32>)
    -> IO(Quic.MultipathConnection & Quic.MultipathConnection):
  (first,+a_params) = a
  (second,+b_params) = b
  do IO<Quic.MultipathConnection & Quic.MultipathConnection>:
    left : Quic.MultipathConnection <- Fixture.validate_peer_parameters((first,a_params))
    right : Quic.MultipathConnection <- Fixture.validate_peer_parameters((second,b_params))
    check_distinct(left,right,Fixture.same_bytes(a_params,b_params))

def check_parameters(first: Quic.MultipathConnection, second: Quic.MultipathConnection)
    -> IO(Quic.MultipathConnection & Quic.MultipathConnection):
  do IO<Quic.MultipathConnection & Quic.MultipathConnection>:
    a : Quic.MultipathConnection & List<&2,U32> <- Fixture.read_peer_parameters(first)
    b : Quic.MultipathConnection & List<&2,U32> <- Fixture.read_peer_parameters(second)
    validate_both(a,b)

def exchange_both(peers: Quic.MultipathConnection & Quic.MultipathConnection) -> IO(Unit):
  (first,second) = peers
  do IO<Unit>:
    exchange(first,55,11,22)
    exchange(second,66,33,44)
    IO.print("PASS Bend served both connections after closing the multipath listener")

def probe_result(result: Quic.MultipathConnection & Probes.Progress,
    next: Quic.MultipathConnection -> Probes.Probe -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  match result:
    case (conn,Probes.Answered{port}):
      do IO<Quic.MultipathConnection>:
        IO.print(String.append("PASS Iroh returned an authenticated PATH_RESPONSE from port ",U32.show(port)))
        return conn
    case (conn,Probes.Pending{probe}):
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        next(conn,probe)
    case (conn,Probes.Failed{code,message}):
      Fixture.reject(Quic.MultipathConnection,conn,code,message)
    case (conn,Probes.TimedOut{}):
      Fixture.reject(Quic.MultipathConnection,conn,1,"Iroh did not return a matching PATH_RESPONSE")

def wait_probe(fuel: Nat, conn: Quic.MultipathConnection, probe: Probes.Probe) -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      Fixture.reject(Quic.MultipathConnection,conn,1,"Iroh did not return a matching PATH_RESPONSE")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        active : Quic.MultipathConnection <- Fixture.step(conn)
        step : Quic.MultipathConnection & Probes.Progress <- Probes.poll(active,probe)
        probe_result(step,next => pending => wait_probe(left,next,pending))

def probe_port(override_port: U32, advertised_port: U32, override_enabled: Bool) -> U32:
  match override_enabled:
    case True{}:
      override_port
    case False{}:
      advertised_port

def challenge_candidate(conn: Quic.MultipathConnection, target: NatState.Candidate, +mode: U32) -> IO(Quic.MultipathConnection):
  NatState.Socket{ip,port} = target
  selected = probe_port(mode,port,U32.is_ge(mode,1024))
  do IO<Quic.MultipathConnection>:
    probe : Probes.Probe <- Probes.start(NatState.Socket{ip,selected},333000)
    wait_probe(10000n,conn,probe)

def server_decision(conn: Quic.MultipathConnection, event: NatState.Transition, mode: U32)
    -> IO(Quic.MultipathConnection):
  match event:
    case NatState.Received{_,NatState.Probe{_,target,_}}:
      do IO<Quic.MultipathConnection>:
        IO.print("PASS Bend decoded Iroh's authenticated REACH_OUT and selected a probe target")
        challenge_candidate(conn,target,mode)
    case _:
      Fixture.reject(Quic.MultipathConnection,conn,1,"expected a NAT probe target")

def decode_reach_out(conn: Quic.MultipathConnection, result: NatWire.DecodeResult, mode: U32)
    -> IO(Quic.MultipathConnection):
  match result:
    case NatWire.Decoded{frame,Nil{}}:
      server_decision(conn,NatState.receive(NatState.start(NatState.Server{True{}},True{},Some{64},Some{32}),frame),mode)
    case _:
      Fixture.reject(Quic.MultipathConnection,conn,1,"invalid NAT traversal frame from transport")

def await_frame(result: Quic.MultipathConnection & Maybe<&1,List<&2,U32>>,
    mode: U32, retry: Quic.MultipathConnection -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  match result:
    case (conn,Some{bytes}):
      decode_reach_out(conn,NatWire.decode(bytes),mode)
    case (conn,None{}):
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        retry(conn)

def wait_nat_frame(fuel: Nat, conn: Quic.MultipathConnection, +mode: U32) -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      Fixture.reject(Quic.MultipathConnection,conn,1,"Iroh did not send REACH_OUT")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        active : Quic.MultipathConnection <- Fixture.step(conn)
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>> <-
          Quic.read_multipath_nat_frame(active)
        pair : Quic.MultipathConnection & Maybe<&1,List<&2,U32>> <- Fixture.ok(Maybe<&1,List<&2,U32>>,result)
        await_frame(pair,mode,next => wait_nat_frame(left,next,mode))

def address_progress(pair: Quic.MultipathConnection & U32,
    retry: Quic.MultipathConnection -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  match pair:
    case (conn,1):
      IO.pure(Quic.MultipathConnection,conn)
    case (conn,_):
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        retry(conn)

def send_candidate_frame(fuel: Nat, conn: Quic.MultipathConnection, +frame: NatWire.Frame)
    -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      Fixture.reject(Quic.MultipathConnection,conn,1,"Iroh did not acknowledge the NAT address frame")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Probes.send_address(conn,frame)
        pair : Quic.MultipathConnection & U32 <- Fixture.ok(U32,result)
        address_progress(pair,next =>
          do IO<Quic.MultipathConnection>:
            stepped : Quic.MultipathConnection <- Fixture.step(next)
            send_candidate_frame(left,stepped,frame))

def confirmed_address_frame(conn: Quic.MultipathConnection, result: NatSend.Change,
    next: Quic.MultipathConnection -> NatSend.LocalState -> IO(Quic.MultipathConnection))
    -> IO(Quic.MultipathConnection):
  match result:
    case NatSend.Changed{state,NatSend.Send{frame}}:
      do IO<Quic.MultipathConnection>:
        sent : Quic.MultipathConnection <- send_candidate_frame(6000n,conn,frame)
        next(sent,state)
    case _:
      Fixture.reject(Quic.MultipathConnection,conn,1,"expected a NAT address frame")

def report_withdrawn(conn: Quic.MultipathConnection, _: NatSend.LocalState) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    IO.print("PASS peer acknowledged the authenticated ADD_ADDRESS and REMOVE_ADDRESS frames")
    return conn

def advertise_candidate(conn: Quic.MultipathConnection, +candidate: NatState.Candidate)
    -> IO(Quic.MultipathConnection):
  state = NatSend.start(NatState.Server{True{}},True{},Some{64},Some{32})
  confirmed_address_frame(conn,NatSend.add(state,candidate),first => next =>
    confirmed_address_frame(first,NatSend.remove(next,candidate),report_withdrawn))

def automatic_probe(result: Probes.ListenerProgress(), retry: Probes.ListenerConnection() -> IO(Probes.ListenerConnection()))
    -> IO(Probes.ListenerConnection()):
  match result:
    case (active,Done{Some{NatState.Socket{_,port}}}):
      do IO<Probes.ListenerConnection()>:
        IO.print(String.append("PASS Iroh returned an authenticated PATH_RESPONSE from port ",U32.show(port)))
        return active
    case (next,Done{None{}}):
      do IO<Probes.ListenerConnection()>:
        IO.sleep(1)
        retry(next)
    case ((conn,_),Fail{(code,message)}):
      Fixture.reject(Probes.ListenerConnection(),conn,code,message)

def wait_automatic(fuel: Nat, connection: Probes.ListenerConnection()) -> IO(Probes.ListenerConnection()):
  match fuel:
    case 0n:
      (conn,_) = connection
      Fixture.reject(Probes.ListenerConnection(),conn,1,"automatic listener did not verify a candidate")
    case 1n+left:
      do IO<Probes.ListenerConnection()>:
        result : Probes.ListenerProgress() <- Probes.step_listener(connection)
        automatic_probe(result,next => wait_automatic(left,next))

def managed_update(pair: Probes.ListenerConnection() & Result<&1,&1,U32 & String,Unit>)
    -> IO(Probes.ListenerConnection()):
  match pair:
    case (active,Done{_}):
      IO.pure(Probes.ListenerConnection(),active)
    case ((conn,_),Fail{(code,message)}):
      Fixture.reject(Probes.ListenerConnection(),conn,code,message)

def finish_managed_updates(conn: Quic.MultipathConnection, state: Probes.ListenerDriver,
    retry: Probes.ListenerConnection() -> IO(Quic.MultipathConnection), pending: Bool) -> IO(Quic.MultipathConnection):
  match pending:
    case True{}:
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        retry((conn,state))
    case False{}:
      do IO<Quic.MultipathConnection>:
        IO.print("PASS Iroh acknowledged the automatic listener's ADD_ADDRESS and REMOVE_ADDRESS")
        return conn

def managed_update_progress(connection: Probes.ListenerConnection(),
    retry: Probes.ListenerConnection() -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  (conn,+state) = connection
  finish_managed_updates(conn,state,retry,Probes.listener_updates_pending(state))

def updates_completed(result: Probes.ListenerProgress(), retry: Probes.ListenerConnection() -> IO(Quic.MultipathConnection))
    -> IO(Quic.MultipathConnection):
  match result:
    case (active,Done{_}):
      managed_update_progress(active,retry)
    case ((conn,_),Fail{(code,message)}):
      Fixture.reject(Quic.MultipathConnection,conn,code,message)

def wait_managed_updates(fuel: Nat, connection: Probes.ListenerConnection()) -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      (conn,_) = connection
      Fixture.reject(Quic.MultipathConnection,conn,1,"automatic listener address update did not get acknowledged")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        result : Probes.ListenerProgress() <- Probes.step_listener(connection)
        updates_completed(result,next => wait_managed_updates(left,next))

def managed_accept_result(result: Probes.AcceptListenerResult(),
    retry: Probes.NatListener() -> IO(Probes.NatListener() & Probes.ListenerConnection()))
    -> IO(Probes.NatListener() & Probes.ListenerConnection()):
  match result:
    case (listener,Done{Some{conn}}):
      IO.pure(Probes.NatListener() & Probes.ListenerConnection(),(listener,conn))
    case (listener,Done{None{}}):
      do IO<Probes.NatListener() & Probes.ListenerConnection()>:
        IO.sleep(1)
        retry(listener)
    case (listener,Fail{(code,message)}):
      do IO<Probes.NatListener() & Probes.ListenerConnection()>:
        Probes.close_listener(listener)
        IO.die(Probes.NatListener() & Probes.ListenerConnection(),code,message)

def managed_accept(fuel: Nat, listener: Probes.NatListener())
    -> IO(Probes.NatListener() & Probes.ListenerConnection()):
  match fuel:
    case 0n:
      do IO<Probes.NatListener() & Probes.ListenerConnection()>:
        Probes.close_listener(listener)
        IO.die(Probes.NatListener() & Probes.ListenerConnection(),1,"automatic listener did not accept Iroh")
    case 1n+left:
      do IO<Probes.NatListener() & Probes.ListenerConnection()>:
        result : Probes.AcceptListenerResult() <- Probes.accept_listener(listener)
        managed_accept_result(result,next => managed_accept(left,next))

def drive_automatic(second: Probes.NatListener() & Probes.ListenerConnection(),
    first: Probes.ListenerConnection(), +address: NatState.Candidate) -> IO(Unit):
  (listener,(right,_)) = second
  do IO<Unit>:
    Probes.close_listener(listener)
    advertised : Probes.ListenerConnection() <- managed_update(Probes.advertise_listener(first,address))
    verified : Probes.ListenerConnection() <- wait_automatic(6000n,advertised)
    withdrawn : Probes.ListenerConnection() <- managed_update(Probes.withdraw_listener(verified,address))
    ready : Quic.MultipathConnection <- wait_managed_updates(6000n,withdrawn)
    exchange_both((ready,right))

def serve_automatic(first: Probes.NatListener() & Probes.ListenerConnection(), address: NatState.Candidate) -> IO(Unit):
  (listener,left) = first
  do IO<Unit>:
    second : Probes.NatListener() & Probes.ListenerConnection() <- managed_accept(16000n,listener)
    drive_automatic(second,left,address)

def exchange_nat(peers: Quic.MultipathConnection & Quic.MultipathConnection, mode: U32, local_address: NatState.Candidate) -> IO(Unit):
  match peers mode:
    case active 0:
      exchange_both(active)
    case active 3:
      exchange_both(active)
    case (left,right) test_port:
      do IO<Unit>:
        first : Quic.MultipathConnection <- wait_nat_frame(6000n,left,test_port)
        advertised : Quic.MultipathConnection <- advertise_candidate(first,local_address)
        exchange_both((advertised,right))

def serve_two(second: Quic.MultipathListener & Quic.MultipathConnection, first: Quic.MultipathConnection,
    +mode: U32, local_address: NatState.Candidate) -> IO(Unit):
  (listener,conn) = second
  do IO<Unit>:
    Quic.close_multipath_listener(listener)
    preferred : Quic.MultipathConnection <- check_selection(first,Fixture.binary_alpn(),mode)
    fallback : Quic.MultipathConnection <- check_selection(conn,Fixture.text_alpn(),mode)
    peers : Quic.MultipathConnection & Quic.MultipathConnection <- check_parameters(preferred,fallback)
    exchange_nat(peers,mode,local_address)

def serve_two_connections(first: Quic.MultipathListener & Quic.MultipathConnection, mode: U32, local_address: NatState.Candidate) -> IO(Unit):
  (listener,conn) = first
  do IO<Unit>:
    second : Quic.MultipathListener & Quic.MultipathConnection <- accept(16000n,listener)
    serve_two(second,conn,mode,local_address)

def updated(result: Quic.MultipathListener & Result<&1,&1,U32 & String,Unit>, expected: U32)
    -> IO(Quic.MultipathListener):
  match result expected:
    case (listener,Done{_}) 0:
      IO.pure(Quic.MultipathListener,listener)
    case (listener,Fail{(22,_)}) 22:
      IO.pure(Quic.MultipathListener,listener)
    case (listener,_) _:
      do IO<Quic.MultipathListener>:
        Quic.close_multipath_listener(listener)
        IO.die(Quic.MultipathListener,1,"unexpected result from ALPN update")

def set_alpns(listener: Quic.MultipathListener, alpns: List<&2,List<&2,U32>>, expected: U32)
    -> IO(Quic.MultipathListener):
  do IO<Quic.MultipathListener>:
    result : Quic.MultipathListener & Result<&1,&1,U32 & String,Unit> <- Quic.set_multipath_alpns(listener,alpns)
    updated(result,expected)

def pause_and_exchange(second: Quic.MultipathListener & Quic.MultipathConnection, first: Quic.MultipathConnection)
    -> IO(Unit):
  (listener,conn) = second
  do IO<Unit>:
    paused : Quic.MultipathListener <- set_alpns(listener,[],0)
    old_protocol : Quic.MultipathConnection <- Fixture.require_alpn(first,Fixture.text_alpn())
    new_protocol : Quic.MultipathConnection <- Fixture.require_alpn(conn,Fixture.binary_alpn())
    IO.print("PAUSED")
    exchange(old_protocol,55,11,22)
    exchange(new_protocol,66,33,44)
    Quic.close_multipath_listener(paused)
    IO.print("PASS both connections survived live ALPN updates")

def reconfigure(first: Quic.MultipathListener & Quic.MultipathConnection) -> IO(Unit):
  (listener,conn) = first
  do IO<Unit>:
    enabled : Quic.MultipathListener <- set_alpns(listener,[Fixture.binary_alpn()],0)
    unchanged : Quic.MultipathListener <- set_alpns(enabled,[[]],22)
    IO.print("SWITCHED")
    second : Quic.MultipathListener & Quic.MultipathConnection <- accept(16000n,unchanged)
    pause_and_exchange(second,conn)

def serve_advertisement(first: Quic.MultipathListener & Quic.MultipathConnection,
    local_address: NatState.Candidate) -> IO(Unit):
  (listener,conn) = first
  do IO<Unit>:
    ready : Quic.MultipathConnection <- advertise_candidate(conn,local_address)
    serve_affinity((listener,ready))

def serve(first: Quic.MultipathListener & Quic.MultipathConnection, mode: U32, local_address: NatState.Candidate) -> IO(Unit):
  match mode:
    case 0:
      serve_two_connections(first,0,local_address)
    case 3:
      serve_two_connections(first,3,local_address)
    case 6:
      serve_two_connections(first,6,local_address)
    case 4:
      reconfigure(first)
    case 1:
      serve_affinity(first)
    case 5:
      serve_affinity(first)
    case 7:
      serve_advertisement(first,local_address)
    case port:
      serve_two_connections(first,port,local_address)

def loopback(host: String, port: U32) -> NatState.Candidate:
  match host:
    case "127.0.0.1":
      NatState.Socket{NatWire.IPv4{[127,0,0,1]},port}
    case _:
      NatState.Socket{NatWire.IPv6{[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]},port}

def announce(bound: Quic.MultipathListener & U32, mode: U32, host: String) -> IO(Unit):
  (listener,+local_port) = bound
  do IO<Unit>:
    IO.print(U32.show(local_port))
    first : Quic.MultipathListener & Quic.MultipathConnection <- accept(16000n,listener)
    serve(first,mode,loopback(host,local_port))

def fixture_peer() -> List<&2,U32>:
  [119,44,138,68,43,125,176,110,22,108,251,193,204,188,188,222,
   111,62,186,118,164,233,142,243,255,197,25,80,34,55,214,239]

def listen_text(+host: String, mode: U32) -> IO(Unit):
  do IO<Unit>:
    bound : Quic.MultipathListener & U32 <- IO.try(Quic.MultipathListener & U32,
      Quic.bind_multipath(host,0,List.replicate(U32,32n,42),fixture_peer(),"iroh-bend/compat/1"))
    announce(bound,mode,host)

def listen_nat_offer(+host: String, mode: U32) -> IO(Unit):
  do IO<Unit>:
    bound : Quic.MultipathListener & U32 <- IO.try(Quic.MultipathListener & U32,
      Quic.bind_multipath_with_nat_limit(host,0,List.replicate(U32,32n,42),fixture_peer(),"iroh-bend/compat/1",64))
    announce(bound,mode,host)

def announce_automatic(bound: Probes.NatListener() & U32, host: String) -> IO(Unit):
  (listener,+port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    first : Probes.NatListener() & Probes.ListenerConnection() <- managed_accept(16000n,listener)
    serve_automatic(first,loopback(host,port))

def listen_automatic(+host: String) -> IO(Unit):
  do IO<Unit>:
    bound : Probes.NatListener() & U32 <- IO.try(Probes.NatListener() & U32,
      Probes.bind_listener(host,0,List.replicate(U32,32n,42),fixture_peer(),[Fixture.text_alpn()],64))
    announce_automatic(bound,host)

def listen_binary(+host: String) -> IO(Unit):
  do IO<Unit>:
    bound : Quic.MultipathListener & U32 <- IO.try(Quic.MultipathListener & U32,
      Quic.bind_multipath_bytes(host,0,List.replicate(U32,32n,42),fixture_peer(),Fixture.binary_alpn()))
    announce(bound,0,host)

def listen_multiple(+host: String) -> IO(Unit):
  do IO<Unit>:
    bound : Quic.MultipathListener & U32 <- IO.try(Quic.MultipathListener & U32,
      Quic.bind_multipath_alpns(host,0,List.replicate(U32,32n,42),fixture_peer(),
        [Fixture.binary_alpn(),Fixture.text_alpn()]))
    announce(bound,3,host)

def enable_live(bound: Quic.MultipathListener & U32, host: String) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    enabled : Quic.MultipathListener <- set_alpns(listener,[Fixture.text_alpn()],0)
    announce((enabled,port),4,host)

def listen_live(+host: String) -> IO(Unit):
  do IO<Unit>:
    bound : Quic.MultipathListener & U32 <- IO.try(Quic.MultipathListener & U32,
      Quic.bind_multipath_alpns(host,0,List.replicate(U32,32n,42),fixture_peer(),[]))
    enable_live(bound,host)

def listen_resumable(+host: String) -> IO(Unit):
  do IO<Unit>:
    bound : Quic.MultipathListener & U32 <- IO.try(Quic.MultipathListener & U32,
      Quic.bind_resumable_multipath(host,0,List.replicate(U32,32n,42),fixture_peer(),Fixture.text_alpn()))
    announce(bound,0,host)

def listen_mode(host: String, number: U32, retry_fixture: Bool) -> IO(Unit):
  match retry_fixture:
    case True{}:
      listen_nat_offer(host,number)
    case False{}:
      listen_text(host,number)

def parse(host: String, mode: Maybe<&2,U32>) -> IO(Unit):
  match mode:
    case Some{2}:
      listen_binary(host)
    case Some{3}:
      listen_multiple(host)
    case Some{4}:
      listen_live(host)
    case Some{5}:
      listen_nat_offer(host,5)
    case Some{6}:
      listen_nat_offer(host,6)
    case Some{7}:
      listen_nat_offer(host,7)
    case Some{8}:
      listen_automatic(host)
    case Some{9}:
      listen_resumable(host)
    case Some{+number}:
      listen_mode(host,number,U32.is_ge(number,1024))
    case None{}:
      IO.die(Unit,2,"expected a listener mode")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{host,Con{port,Nil{}}}}:
      parse(host,U32.read(port))
    case _:
      IO.die(Unit,2,"expected a host and listener mode")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
