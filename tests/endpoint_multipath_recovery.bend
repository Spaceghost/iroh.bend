import Base
import ../src/endpoint.bend as Endpoint
import ../src/endpoint_multipath.bend as Multipath
import ../src/quic_multipath.bend as Quic
import ./quic_multipath_bend.bend as Fixture

def fixture_alpn() -> List<&2,U32>:
  [105,114,111,104,45,98,101,110,100,47,99,111,109,112,97,116,47,49]

def routed_fail(-T: Type, owner: Multipath.RoutedConnection, code: U32, message: String) -> IO(T):
  do IO<T>:
    _ : Result<&1,&1,U32 & String,Unit> <- Multipath.close_routes(owner)
    IO.die(T,code,message)

def await_recovery(progress: Multipath.RoutedConnection & Multipath.PathResult(),
    retry: Multipath.RoutedConnection -> IO(Multipath.RoutedConnection)) -> IO(Multipath.RoutedConnection):
  match progress:
    case (owner,Done{Multipath.RecoveredRelay{_}}):
      IO.pure(Multipath.RoutedConnection,owner)
    case (owner,Done{_}):
      do IO<Multipath.RoutedConnection>:
        IO.sleep(1)
        retry(owner)
    case (owner,Fail{(code,message)}):
      routed_fail(Multipath.RoutedConnection,owner,code,message)

def wait_recovery(fuel: Nat, owner: Multipath.RoutedConnection) -> IO(Multipath.RoutedConnection):
  match fuel:
    case 0n:
      routed_fail(Multipath.RoutedConnection,owner,1,"direct path loss did not activate the relay")
    case 1n+left:
      do IO<Multipath.RoutedConnection>:
        progress : Multipath.RoutedConnection & Multipath.PathResult() <- Multipath.step_routes(owner)
        await_recovery(progress,next => wait_recovery(left,next))

def await_standby(progress: Multipath.RoutedConnection & Multipath.PathResult(),
    retry: Multipath.RoutedConnection -> IO(Multipath.RoutedConnection)) -> IO(Multipath.RoutedConnection):
  match progress:
    case (Multipath.Routed{conn,candidates,Multipath.Backup{plan,Multipath.StandbyBackup{path}}},Done{_}):
      IO.pure(Multipath.RoutedConnection,
        Multipath.Routed{conn,candidates,Multipath.Backup{plan,Multipath.StandbyBackup{path}}})
    case (owner,Done{_}):
      do IO<Multipath.RoutedConnection>:
        IO.sleep(1)
        retry(owner)
    case (owner,Fail{(code,message)}):
      routed_fail(Multipath.RoutedConnection,owner,code,message)

def wait_standby(fuel: Nat, owner: Multipath.RoutedConnection) -> IO(Multipath.RoutedConnection):
  match fuel:
    case 0n:
      routed_fail(Multipath.RoutedConnection,owner,1,"relay standby path did not validate")
    case 1n+left:
      do IO<Multipath.RoutedConnection>:
        progress : Multipath.RoutedConnection & Multipath.PathResult() <- Multipath.step_routes(owner)
        await_standby(progress,next => wait_standby(left,next))

def recovery_prefix_ack(sent: Quic.MultipathConnection & U32) -> IO(Quic.MultipathConnection & U32):
  (conn,stream) = sent
  do IO<Quic.MultipathConnection & U32>:
    next : Quic.MultipathConnection <- Fixture.read_datagram(4000n,conn,[12])
    return (next,stream)

def recovery_prefix(opened: Quic.MultipathConnection & U32) -> IO(Quic.MultipathConnection & U32):
  (conn,+stream) = opened
  do IO<Quic.MultipathConnection & U32>:
    queued : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.write_multipath_stream(conn,stream,[11],0)
    result : Quic.MultipathConnection & U32 <- Fixture.ok(U32,queued)
    kept : Quic.MultipathConnection & U32 <- Fixture.write_result(result,stream)
    recovery_prefix_ack(kept)

def open_recovery_stream(conn: Quic.MultipathConnection) -> IO(Quic.MultipathConnection & U32):
  do IO<Quic.MultipathConnection & U32>:
    opened : Quic.MultipathConnection & U32 <- Fixture.open(conn)
    recovery_prefix(opened)

def finish_recovery(sent: Multipath.RoutedConnection & U32) -> IO(Unit):
  (owner,stream) = sent
  Multipath.Routed{(conn,bridge),_,_} = owner
  do IO<Unit>:
    read : Quic.MultipathConnection <- Fixture.receive(5000n,conn,stream,23,False{})
    IO.try(Unit,Multipath.disconnect((read,bridge)))
    IO.print("PASS open stream continued on the relay after direct path loss")

def cut_direct(primed: Multipath.RoutedConnection & U32) -> IO(Unit):
  (owner,stream) = primed
  do IO<Unit>:
    IO.print("CUT_DIRECT")
    recovered : Multipath.RoutedConnection <- wait_recovery(9000n,owner)
    sent : Multipath.RoutedConnection & U32 <-
      Multipath.use_routed_connection(U32,recovered,c => Fixture.write_assigned((c,Unit{}),stream,22))
    finish_recovery(sent)

def recover(host: String, port: Maybe<&2,U32>, url: String) -> IO(Unit):
  match port:
    case Some{target}:
      do IO<Unit>:
        owner : Multipath.RoutedConnection <- IO.try(Multipath.RoutedConnection,
          Multipath.connect_routed(Endpoint.DialRoutes{[Endpoint.IpAddress{host,target}],[url]},
            Endpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.fixture_key(0),fixture_alpn()},
            Endpoint.HandshakeTimeouts{3500,6000}))
        ready : Multipath.RoutedConnection <- wait_standby(6500n,owner)
        primed : Multipath.RoutedConnection & U32 <- Multipath.use_routed_connection(U32,ready,open_recovery_stream)
        cut_direct(primed)
    case None{}:
      IO.die(Unit,2,"expected the peer port")

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,host,port,url]:
      recover(host,U32.read(port),url)
    case _:
      IO.die(Unit,2,"expected a peer address and relay URL")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
