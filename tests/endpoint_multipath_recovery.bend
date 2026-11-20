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

def write_chunk(opened: Quic.MultipathConnection & U32, byte: U32, fin: U32) -> IO(Quic.MultipathConnection & U32):
  (conn,+stream) = opened
  do IO<Quic.MultipathConnection & U32>:
    queued : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.write_multipath_stream(conn,stream,[byte],fin)
    result : Quic.MultipathConnection & U32 <- Fixture.ok(U32,queued)
    Fixture.write_result(result,stream)

def open_recovery_stream(conn: Quic.MultipathConnection) -> IO(Quic.MultipathConnection & U32):
  do IO<Quic.MultipathConnection & U32>:
    opened : Quic.MultipathConnection & U32 <- Fixture.open(conn)
    written : Quic.MultipathConnection & U32 <- write_chunk(opened,11,0)
    recovery_prefix_ack(written)

def finish_recovery(sent: Multipath.RoutedConnection & U32, reply: U32, message: String) -> IO(Unit):
  (owner,stream) = sent
  Multipath.Routed{(conn,bridge),_,_} = owner
  do IO<Unit>:
    read : Quic.MultipathConnection <- Fixture.receive(5000n,conn,stream,reply,False{})
    IO.try(Unit,Multipath.disconnect((read,bridge)))
    IO.print(message)

def wait_more(owner: Multipath.RoutedConnection, attempted: Bool,
    retry: Multipath.RoutedConnection -> Bool -> IO(Multipath.RoutedConnection)) -> IO(Multipath.RoutedConnection):
  do IO<Multipath.RoutedConnection>:
    IO.sleep(1)
    retry(owner,attempted)

def await_probe_timeout(progress: Multipath.RoutedConnection & Multipath.PathResult(), attempted: Bool,
    retry: Multipath.RoutedConnection -> Bool -> IO(Multipath.RoutedConnection)) -> IO(Multipath.RoutedConnection):
  match progress attempted:
    case (Multipath.Routed{conn,candidates,Multipath.Rechecking{relay,Multipath.Waiting{since}}},Done{_}) True{}:
      IO.pure(Multipath.RoutedConnection,Multipath.Routed{conn,candidates,Multipath.Rechecking{relay,Multipath.Waiting{since}}})
    case (Multipath.Routed{conn,candidates,Multipath.Rechecking{relay,Multipath.Validating{rest,path,since}}},Done{_}) _:
      wait_more(Multipath.Routed{conn,candidates,Multipath.Rechecking{relay,Multipath.Validating{rest,path,since}}},True{},retry)
    case (owner,Done{_}) _:
      wait_more(owner,attempted,retry)
    case (owner,Fail{(code,message)}) _:
      routed_fail(Multipath.RoutedConnection,owner,code,message)

def wait_probe_timeout(fuel: Nat, owner: Multipath.RoutedConnection, attempted: Bool) -> IO(Multipath.RoutedConnection):
  match fuel:
    case 0n:
      routed_fail(Multipath.RoutedConnection,owner,1,"the published address was not probed again")
    case 1n+left:
      do IO<Multipath.RoutedConnection>:
        progress : Multipath.RoutedConnection & Multipath.PathResult() <- Multipath.step_routes(owner)
        await_probe_timeout(progress,attempted,next => seen => wait_probe_timeout(left,next,seen))

def await_direct(progress: Multipath.RoutedConnection & Multipath.PathResult(),
    retry: Multipath.RoutedConnection -> IO(Multipath.RoutedConnection)) -> IO(Multipath.RoutedConnection):
  match progress:
    case (owner,Done{Multipath.PromotedPath{_}}):
      IO.pure(Multipath.RoutedConnection,owner)
    case (owner,Done{_}):
      do IO<Multipath.RoutedConnection>:
        IO.sleep(1)
        retry(owner)
    case (owner,Fail{(code,message)}):
      routed_fail(Multipath.RoutedConnection,owner,code,message)

def wait_direct(fuel: Nat, owner: Multipath.RoutedConnection) -> IO(Multipath.RoutedConnection):
  match fuel:
    case 0n:
      routed_fail(Multipath.RoutedConnection,owner,1,"the restored UDP route was not promoted")
    case 1n+left:
      do IO<Multipath.RoutedConnection>:
        progress : Multipath.RoutedConnection & Multipath.PathResult() <- Multipath.step_routes(owner)
        await_direct(progress,next => wait_direct(left,next))

def recovery_ack(conn: Quic.MultipathConnection, byte: U32) -> IO(Quic.MultipathConnection & Unit):
  do IO<Quic.MultipathConnection & Unit>:
    received : Quic.MultipathConnection <- Fixture.read_datagram(4000n,conn,[byte])
    return (received,Unit{})

def second_cut(acknowledged: Multipath.RoutedConnection & Unit, stream: U32) -> IO(Unit):
  (owner,_) = acknowledged
  do IO<Unit>:
    IO.print("CUT_DIRECT")
    recovered : Multipath.RoutedConnection <- wait_recovery(9000n,owner)
    sent : Multipath.RoutedConnection & U32 <-
      Multipath.use_routed_connection(U32,recovered,c => write_chunk((c,stream),44,1))
    finish_recovery(sent,45,"PASS open stream survived direct UDP restoration and a second outage")

def confirm_restoration(sent: Multipath.RoutedConnection & U32) -> IO(Unit):
  (owner,stream) = sent
  do IO<Unit>:
    acknowledged : Multipath.RoutedConnection & Unit <-
      Multipath.use_routed_connection(Unit,owner,c => recovery_ack(c,34))
    second_cut(acknowledged,stream)

def resume_after_ack(pair: Multipath.RoutedConnection & Unit, stream: U32) -> IO(Unit):
  (owner,_) = pair
  do IO<Unit>:
    blocked : Multipath.RoutedConnection <- wait_probe_timeout(6500n,owner,False{})
    IO.print("RESTORE_DIRECT")
    direct : Multipath.RoutedConnection <- wait_direct(7000n,blocked)
    next : Multipath.RoutedConnection & U32 <-
      Multipath.use_routed_connection(U32,direct,c => write_chunk((c,stream),33,0))
    confirm_restoration(next)

def restore_route(sent: Multipath.RoutedConnection & U32) -> IO(Unit):
  (owner,stream) = sent
  do IO<Unit>:
    acknowledged : Multipath.RoutedConnection & Unit <-
      Multipath.use_routed_connection(Unit,owner,c => recovery_ack(c,23))
    resume_after_ack(acknowledged,stream)

def send_over_relay(owner: Multipath.RoutedConnection, stream: U32, restore: Bool) -> IO(Unit):
  match restore:
    case True{}:
      do IO<Unit>:
        sent : Multipath.RoutedConnection & U32 <-
          Multipath.use_routed_connection(U32,owner,c => write_chunk((c,stream),22,0))
        restore_route(sent)
    case False{}:
      do IO<Unit>:
        sent : Multipath.RoutedConnection & U32 <-
          Multipath.use_routed_connection(U32,owner,c => write_chunk((c,stream),22,1))
        finish_recovery(sent,23,"PASS open stream continued on the relay after direct path loss")

def cut_direct(primed: Multipath.RoutedConnection & U32, restore: Bool) -> IO(Unit):
  (owner,stream) = primed
  do IO<Unit>:
    IO.print("CUT_DIRECT")
    recovered : Multipath.RoutedConnection <- wait_recovery(9000n,owner)
    send_over_relay(recovered,stream,restore)

def recover(host: String, port: Maybe<&2,U32>, url: String, restore: Bool) -> IO(Unit):
  match port:
    case Some{target}:
      do IO<Unit>:
        owner : Multipath.RoutedConnection <- IO.try(Multipath.RoutedConnection,
          Multipath.connect_routed(Endpoint.DialRoutes{[Endpoint.IpAddress{host,target}],[url]},
            Endpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.fixture_key(0),fixture_alpn()},
            Endpoint.HandshakeTimeouts{3500,6000}))
        ready : Multipath.RoutedConnection <- wait_standby(6500n,owner)
        primed : Multipath.RoutedConnection & U32 <- Multipath.use_routed_connection(U32,ready,open_recovery_stream)
        cut_direct(primed,restore)
    case None{}:
      IO.die(Unit,2,"expected the peer port")

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,host,port,url]:
      recover(host,U32.read(port),url,False{})
    case [_,host,port,url,"restore"]:
      recover(host,U32.read(port),url,True{})
    case _:
      IO.die(Unit,2,"expected a peer address and relay URL")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
