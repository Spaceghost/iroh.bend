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

def exchange(owner: Nat.ListenerConnection(), port: U32, blackhole: U32) -> IO(Unit):
  (conn,driver) = owner
  do IO<Unit>:
    datagrams : Quic.MultipathConnection <- Listener.datagram_echo(conn)
    stream : Quic.MultipathConnection & U32 <- Listener.incoming(4000n,datagrams,0)
    relayed : Quic.MultipathConnection <- Listener.echo(stream,0,11)
    advertised : Nat.ListenerConnection() <- Listener.managed_update(
      Nat.advertise_listener((relayed,driver),State.Socket{Wire.IPv6{[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]},blackhole}))
    pump(900n,advertised,active => advertise_working(active,port))

def serve(accepted: Nat.NatListener() & Nat.ListenerConnection(), port: U32, blackhole: U32) -> IO(Unit):
  (listener,conn) = accepted
  do IO<Unit>:
    Nat.close_listener(listener)
    exchange(conn,port,blackhole)

def stop_bridge(binding: Relay.Bridge & U32) -> IO(Unit):
  (bridge,_) = binding
  IO.try(Unit,Relay.stop(bridge))

def listen(bound: Nat.NatListener() & U32, relay: String, blackhole: U32) -> IO(Unit):
  (listener,+port) = bound
  do IO<Unit>:
    bridge : Relay.Bridge & U32 <- IO.try(Relay.Bridge & U32,
      Relay.start(relay,List.replicate(U32,32n,42),Listener.fixture_peer(),port))
    IO.print("READY")
    accepted : Nat.NatListener() & Nat.ListenerConnection() <- Listener.managed_accept(9000n,listener)
    serve(accepted,port,blackhole)
    stop_bridge(bridge)

def run(relay: String, port: Maybe<&2,U32>, capacity: Maybe<&2,U32>) -> IO(Unit):
  match port capacity:
    case Some{blackhole} Some{limit}:
      do IO<Unit>:
        bound : Nat.NatListener() & U32 <- IO.try(Nat.NatListener() & U32,
          Nat.bind_listener("127.0.0.1",0,List.replicate(U32,32n,42),Listener.fixture_peer(),[Fixture.text_alpn()],limit))
        listen(bound,relay,blackhole)
    case _ _:
      IO.die(Unit,2,"expected the dead IPv6 UDP port and candidate limit")

def args(input: List<String>) -> IO(Unit):
  match input:
    case [_,relay,port,width]:
      run(relay,U32.read(port),U32.read(width))
    case _:
      IO.die(Unit,2,"expected the relay URL, dead IPv6 UDP port and candidate limit")

def main() -> IO(Unit):
  do IO<Unit>:
    input : List<String> <- IO.args()
    args(input)
