import Base
import ../src/quic_multipath.bend as Quic
import ../src/quic_multipath_nat.bend as Nat
import ../src/quic_nat.bend as Wire
import ../src/quic_nat_state.bend as State
import ../src/relay_quic.bend as Relay
import ./quic_multipath_bend.bend as Fixture
import ./quic_multipath_listener.bend as Listener

def drained(owner: Nat.ListenerConnection(), next: Quic.MultipathConnection -> IO(Unit), pending: Bool) -> IO(Unit):
  (conn,_) = owner
  match pending:
    case False{}:
      next(conn)
    case True{}:
      Fixture.reject(Unit,conn,1,"address advertisement remained unacknowledged")

def after_delay(owner: Nat.ListenerConnection(), next: Quic.MultipathConnection -> IO(Unit)) -> IO(Unit):
  (conn,+state) = owner
  drained((conn,state),next,Nat.listener_updates_pending(state))

def tick(progress: Nat.ListenerProgress(), resume: Nat.ListenerConnection() -> IO(Unit)) -> IO(Unit):
  match progress:
    case (owner,Done{_}):
      do IO<Unit>:
        IO.sleep(1)
        resume(owner)
    case ((conn,_),Fail{(code,message)}):
      Fixture.reject(Unit,conn,code,message)

def pump(fuel: Nat, owner: Nat.ListenerConnection(), next: Nat.ListenerConnection() -> IO(Unit)) -> IO(Unit):
  match fuel:
    case 0n:
      next(owner)
    case 1n+left:
      do IO<Unit>:
        progress : Nat.ListenerProgress() <- Nat.step_listener(owner)
        tick(progress,active => pump(left,active,next))

def reply_direct(path: Quic.MultipathConnection & U32) -> IO(Unit):
  (conn,id) = path
  do IO<Unit>:
    stream : Quic.MultipathConnection & U32 <- Listener.incoming(4000n,conn,0)
    echoed : Quic.MultipathConnection <- Listener.echo(stream,id,22)
    Listener.wait_close(4000n,echoed)

def finish(conn: Quic.MultipathConnection) -> IO(Unit):
  do IO<Unit>:
    path : Quic.MultipathConnection & U32 <- Listener.wait_path(4000n,conn)
    reply_direct(path)

def advertise_working(owner: Nat.ListenerConnection(), port: U32) -> IO(Unit):
  do IO<Unit>:
    advertised : Nat.ListenerConnection() <- Listener.managed_update(
      Nat.advertise_listener(owner,State.Socket{Wire.IPv4{[127,0,0,1]},port}))
    pump(500n,advertised,ready => after_delay(ready,finish))

def mapping_matches(input: Wire.DecodeResult, port: U32) -> Bool:
  match input:
    case Wire.Decoded{Wire.ReachOut{_,Wire.IPv4{[127,0,0,1]},observed},Nil{}}:
      U32.is_eq(port,observed)
    case Wire.Decoded{Wire.ReachOut{_,Wire.IPv6{[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]},observed},Nil{}}:
      U32.is_eq(port,observed)
    case _:
      False{}

def frame_matches(frame: Maybe<&1,List<&2,U32>>, port: U32) -> Bool:
  match frame:
    case Some{bytes}:
      mapping_matches(Wire.decode(bytes),port)
    case None{}:
      False{}

def mapping_progress(conn: Quic.MultipathConnection,
    next: Quic.MultipathConnection -> IO(Quic.MultipathConnection), observed: Bool) -> IO(Quic.MultipathConnection):
  match observed:
    case True{}:
      do IO<Quic.MultipathConnection>:
        IO.print("PASS routed endpoint advertised the relay-observed UDP mapping")
        return conn
    case False{}:
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        next(conn)

def check_mapping(pair: Quic.MultipathConnection & Maybe<&1,List<&2,U32>>, port: U32,
    next: Quic.MultipathConnection -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  (conn,frame) = pair
  mapping_progress(conn,next,frame_matches(frame,port))

def wait_mapping(fuel: Nat, conn: Quic.MultipathConnection, +port: U32) -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      Fixture.reject(Quic.MultipathConnection,conn,1,"expected a REACH_OUT with the relay-observed mapping")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        ready : Quic.MultipathConnection <- Fixture.step(conn)
        frame : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>> <-
          Quic.read_multipath_nat_frame(ready)
        decoded : Quic.MultipathConnection & Maybe<&1,List<&2,U32>> <- Fixture.ok(Maybe<&1,List<&2,U32>>,frame)
        check_mapping(decoded,port,active => wait_mapping(left,active,port))

def wait_refresh(path: Quic.MultipathConnection & U32, refreshed: U32) -> IO(Unit):
  (conn,id) = path
  do IO<Unit>:
    updated : Quic.MultipathConnection <- wait_mapping(39000n,conn,refreshed)
    reply_direct((updated,id))

def finish_mapping(conn: Quic.MultipathConnection, refreshed: U32) -> IO(Unit):
  match refreshed:
    case 0:
      finish(conn)
    case port:
      do IO<Unit>:
        path : Quic.MultipathConnection & U32 <- Listener.wait_path(4000n,conn)
        wait_refresh(path,port)

def advertise_mapping(conn: Quic.MultipathConnection, blackhole: State.Candidate, port: U32, mapped: U32, refreshed: U32) -> IO(Unit):
  State.Socket{ip,dead_port} = blackhole
  do IO<Unit>:
    advertised : Quic.MultipathConnection <- Listener.send_candidate_frame(3000n,conn,
      Wire.AddAddress{Wire.Var{0,0},ip,dead_port})
    mapped_conn : Quic.MultipathConnection <- wait_mapping(4000n,advertised,mapped)
    working : Quic.MultipathConnection <- Listener.send_candidate_frame(3000n,mapped_conn,
      Wire.AddAddress{Wire.Var{0,1},Wire.IPv4{[127,0,0,1]},port})
    finish_mapping(working,refreshed)

def advertise_first(conn: Quic.MultipathConnection, driver: Nat.ListenerDriver, port: U32, blackhole: State.Candidate,
    expected: U32, refreshed: U32) -> IO(Unit):
  match expected:
    case 0:
      do IO<Unit>:
        advertised : Nat.ListenerConnection() <- Listener.managed_update(
          Nat.advertise_listener((conn,driver),blackhole))
        pump(900n,advertised,active => advertise_working(active,port))
    case mapped:
      advertise_mapping(conn,blackhole,port,mapped,refreshed)

def exchange(owner: Nat.ListenerConnection(), port: U32, blackhole: State.Candidate, expected: U32, refreshed: U32) -> IO(Unit):
  (conn,driver) = owner
  do IO<Unit>:
    datagrams : Quic.MultipathConnection <- Listener.datagram_echo(conn)
    stream : Quic.MultipathConnection & U32 <- Listener.incoming(4000n,datagrams,0)
    relayed : Quic.MultipathConnection <- Listener.echo(stream,0,11)
    advertise_first(relayed,driver,port,blackhole,expected,refreshed)

def serve(accepted: Nat.NatListener() & Nat.ListenerConnection(), port: U32, blackhole: State.Candidate, expected: U32, refreshed: U32) -> IO(Unit):
  (listener,conn) = accepted
  do IO<Unit>:
    Nat.close_listener(listener)
    exchange(conn,port,blackhole,expected,refreshed)

def stop_bridge(binding: Relay.Bridge & U32) -> IO(Unit):
  (bridge,_) = binding
  IO.try(Unit,Relay.stop(bridge))

def listen(bound: Nat.NatListener() & U32, relay: String, blackhole: State.Candidate, expected: U32, refreshed: U32) -> IO(Unit):
  (listener,+port) = bound
  do IO<Unit>:
    bridge : Relay.Bridge & U32 <- IO.try(Relay.Bridge & U32,
      Relay.start(relay,List.replicate(U32,32n,42),Listener.fixture_peer(),port))
    IO.print("READY")
    accepted : Nat.NatListener() & Nat.ListenerConnection() <- Listener.managed_accept(9000n,listener)
    serve(accepted,port,blackhole,expected,refreshed)
    stop_bridge(bridge)

def loopback_address(ipv6: Bool) -> Wire.Address:
  match ipv6:
    case True{}:
      Wire.IPv6{[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]}
    case False{}:
      Wire.IPv4{[127,0,0,1]}

def run(relay: String, port: Maybe<&2,U32>, capacity: Maybe<&2,U32>, mapped: Maybe<&2,U32>, ipv6: Bool, refreshed: Maybe<&2,U32>) -> IO(Unit):
  match port capacity mapped refreshed:
    case Some{blackhole} Some{limit} Some{expected} Some{replacement}:
      do IO<Unit>:
        bound : Nat.NatListener() & U32 <- IO.try(Nat.NatListener() & U32,
          Nat.bind_listener("127.0.0.1",0,List.replicate(U32,32n,42),Listener.fixture_peer(),[Fixture.text_alpn()],limit))
        listen(bound,relay,State.Socket{loopback_address(ipv6),blackhole},expected,replacement)
    case _ _ _ _:
      IO.die(Unit,2,"expected the dead UDP port, candidate limit and mapped port")

def args(input: List<String>) -> IO(Unit):
  match input:
    case [_,relay,port,width,mapped,family,replacement]:
      run(relay,U32.read(port),U32.read(width),U32.read(mapped),String.starts_with(family,"6"),U32.read(replacement))
    case _:
      IO.die(Unit,2,"expected the relay URL, dead UDP port, candidate limit, mapped port and address family")

def main() -> IO(Unit):
  do IO<Unit>:
    input : List<String> <- IO.args()
    args(input)
