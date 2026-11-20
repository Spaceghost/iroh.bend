import Base
import ../src/endpoint.bend as Endpoint
import ../src/quic_datagram.bend as Quic
import ../src/relay_quic.bend as Relay
import ./quic_datagram.bend as Fixture
import ./quic_migration.bend as Migration

def begin_result(outcome: Endpoint.Connection() & Result<&1,&1,U32 & String,U32>,
    retry: Endpoint.Connection() -> IO(Endpoint.Connection())) -> IO(Endpoint.Connection()):
  match outcome:
    case (waiting,Done{0}):
      do IO<Endpoint.Connection()>:
        IO.sleep(1)
        retry(waiting)
    case (validating,Done{_}):
      IO.pure(Endpoint.Connection(),validating)
    case (failed,Fail{(code,message)}):
      do IO<Endpoint.Connection()>:
        _ : Result<&1,&1,U32 & String,Unit> <- Endpoint.disconnect(failed)
        IO.die(Endpoint.Connection(),code,message)

def begin(fuel: Nat, connected: Endpoint.Connection(), +host: String, +port: U32) -> IO(Endpoint.Connection()):
  match fuel:
    case 0n:
      do IO<Endpoint.Connection()>:
        _ : Result<&1,&1,U32 & String,Unit> <- Endpoint.disconnect(connected)
        IO.die(Endpoint.Connection(),1,"direct path validation did not start")
    case 1n+left:
      (conn,bridge) = connected
      do IO<Endpoint.Connection()>:
        stepped : Quic.DatagramConnection <- Fixture.step(conn)
        started : Endpoint.Connection() & Result<&1,&1,U32 & String,U32> <-
          Endpoint.start_path_migration((stepped,bridge),Endpoint.IpAddress{host,0},Endpoint.IpAddress{host,port})
        begin_result(started,next => begin(left,next,host,port))

def switch_to_direct(connected: Endpoint.Connection(), stream: U32) -> IO(Unit):
  match connected:
    case (conn,Some{bridge}):
      do IO<Unit>:
        validation : Quic.DatagramConnection & U32 <- Migration.await_move(12000n,conn)
        direct : Quic.DatagramConnection <- Migration.check_move(validation,2)
        IO.try(Unit,Relay.stop(bridge))
        IO.print("PASS direct path validated and Bend closed the relay bridge")
        Migration.finish_stream(direct,stream)
    case (conn,None{}):
      do IO<Unit>:
        Quic.drop_quic_datagram(conn)
        IO.die(Unit,1,"connection did not start on the relay")

def switch_to_relay(connected: Endpoint.Connection(), stream: U32) -> IO(Unit):
  match connected:
    case (conn,Some{bridge}):
      do IO<Unit>:
        validation : Quic.DatagramConnection & U32 <- Migration.await_move(12000n,conn)
        relayed : Quic.DatagramConnection <- Migration.check_move(validation,2)
        IO.print("PASS relay path validated")
        Migration.finish_stream(relayed,stream)
        IO.try(Unit,Relay.stop(bridge))
    case (conn,None{}):
      do IO<Unit>:
        Quic.drop_quic_datagram(conn)
        IO.die(Unit,1,"connection is missing the relay bridge")

def probe_relay(primed: Quic.DatagramConnection & U32, attached: Relay.Bridge & U32) -> IO(Unit):
  (conn,stream) = primed
  (bridge,port) = attached
  do IO<Unit>:
    validating : Endpoint.Connection() <- begin(2500n,(conn,Some{bridge}),"127.0.0.1",port)
    switch_to_relay(validating,stream)

def move_to_relay(primed: Quic.DatagramConnection & U32, url: String) -> IO(Unit):
  do IO<Unit>:
    attached : Relay.Bridge & U32 <- IO.try(Relay.Bridge & U32,
      Relay.start(url,List.replicate(U32,32n,73),Fixture.public_key(False{}),0))
    probe_relay(primed,attached)

def move_to_direct(primed: Quic.DatagramConnection & U32, bridge: Maybe<&1,Relay.Bridge>, host: String, port: U32) -> IO(Unit):
  (conn,stream) = primed
  do IO<Unit>:
    validating : Endpoint.Connection() <- begin(2500n,(conn,bridge),host,port)
    switch_to_direct(validating,stream)

def exercise(connected: Endpoint.Connection(), host: String, port: U32) -> IO(Unit):
  (conn,bridge) = connected
  do IO<Unit>:
    opened : Quic.DatagramConnection & U32 <- Fixture.poll_stream(2500n,conn,Fixture.OpenStream{0})
    primed : Quic.DatagramConnection & U32 <- Migration.prime_stream(opened)
    move_to_direct(primed,bridge,host,port)

def open_direct(conn: Quic.DatagramConnection, url: String) -> IO(Unit):
  do IO<Unit>:
    opened : Quic.DatagramConnection & U32 <- Fixture.poll_stream(2500n,conn,Fixture.OpenStream{0})
    primed : Quic.DatagramConnection & U32 <- Migration.prime_stream(opened)
    move_to_relay(primed,url)

def dial_direct_then_relay(url: String, host: String, port: U32) -> IO(Unit):
  do IO<Unit>:
    conn : Quic.DatagramConnection <- IO.try(Quic.DatagramConnection,
      Quic.connect(host,port,List.replicate(U32,32n,73),Fixture.public_key(False{}),Fixture.fixture_alpn(),6000n))
    open_direct(conn,url)

def fail_routed(-T: Type, owner: Endpoint.RoutedConnection, code: U32, message: String) -> IO(T):
  do IO<T>:
    _ : Result<&1,&1,U32 & String,Unit> <- Endpoint.close_routes(owner)
    IO.die(T,code,message)

def await_relay(progress: Endpoint.RouteStep(),
    retry: Endpoint.RoutedConnection -> IO(Endpoint.RoutedConnection)) -> IO(Endpoint.RoutedConnection):
  match progress:
    case (owner,Done{Endpoint.RelayRoute{}}):
      IO.pure(Endpoint.RoutedConnection,owner)
    case (owner,Done{Endpoint.DirectRoute{}}):
      do IO<Endpoint.RoutedConnection>:
        IO.sleep(1)
        retry(owner)
    case (owner,Fail{(code,message)}):
      fail_routed(Endpoint.RoutedConnection,owner,code,message)

def wait_for_relay(fuel: Nat, owner: Endpoint.RoutedConnection) -> IO(Endpoint.RoutedConnection):
  match fuel:
    case 0n:
      fail_routed(Endpoint.RoutedConnection,owner,1,"direct outage did not recover via relay")
    case 1n+left:
      do IO<Endpoint.RoutedConnection>:
        progress : Endpoint.RouteStep() <- Endpoint.step_routes(owner)
        await_relay(progress,next => wait_for_relay(left,next))

def finish_routed(owner: Endpoint.RoutedConnection, stream: U32) -> IO(Unit):
  Endpoint.Routed{transport,_} = owner
  switch_to_relay(transport,stream)

def still_direct(progress: Endpoint.RouteStep(), expired: Bool,
    next: Endpoint.RoutedConnection -> IO(Endpoint.RoutedConnection)) -> IO(Endpoint.RoutedConnection):
  match progress expired:
    case (Endpoint.Routed{conn,Endpoint.Watching{plan}},Done{Endpoint.DirectRoute{}}) True{}:
      IO.pure(Endpoint.RoutedConnection,Endpoint.Routed{conn,Endpoint.Watching{plan}})
    case (Endpoint.Routed{conn,Endpoint.Watching{plan}},Done{Endpoint.DirectRoute{}}) False{}:
      do IO<Endpoint.RoutedConnection>:
        IO.sleep(1)
        next(Endpoint.Routed{conn,Endpoint.Watching{plan}})
    case (owner,Fail{(code,message)}) _:
      fail_routed(Endpoint.RoutedConnection,owner,code,message)
    case (owner,Done{_}) _:
      fail_routed(Endpoint.RoutedConnection,owner,1,"healthy idle QUIC connection tried the relay")

def observe_healthy(fuel: Nat, owner: Endpoint.RoutedConnection, +since: U32) -> IO(Endpoint.RoutedConnection):
  match fuel:
    case 0n:
      fail_routed(Endpoint.RoutedConnection,owner,1,"the healthy path observation window did not elapse")
    case 1n+left:
      do IO<Endpoint.RoutedConnection>:
        progress : Endpoint.RouteStep() <- Endpoint.step_routes(owner)
        now : U32 <- Quic.quic_millis()
        still_direct(progress,U32.is_ge(U32.sub(now,since),4250),next => observe_healthy(left,next,since))

def send_byte(conn: Quic.DatagramConnection, +stream: U32, byte: U32, fin: U32)
    -> IO(Quic.DatagramConnection):
  do IO<Quic.DatagramConnection>:
    queued : Quic.DatagramConnection <- Fixture.stream_submit(conn,Fixture.QueueStream{stream,[byte],fin})
    Fixture.stream_submit(queued,Fixture.FlushStream{stream})

def send_and_ack(conn: Quic.DatagramConnection, stream: U32, byte: U32, ack: U32)
    -> IO(Quic.DatagramConnection & Unit):
  do IO<Quic.DatagramConnection & Unit>:
    sent : Quic.DatagramConnection <- send_byte(conn,stream,byte,0)
    ready : Quic.DatagramConnection <- Fixture.receive_reply(4000n,sent,[ack,0,255])
    return (ready,Unit{})

def wait_more(owner: Endpoint.RoutedConnection, attempted: Bool,
    next: Endpoint.RoutedConnection -> Bool -> IO(Endpoint.RoutedConnection)) -> IO(Endpoint.RoutedConnection):
  do IO<Endpoint.RoutedConnection>:
    IO.sleep(1)
    next(owner,attempted)

def saw_failed_probe(progress: Endpoint.RouteStep(), attempted: Bool,
    next: Endpoint.RoutedConnection -> Bool -> IO(Endpoint.RoutedConnection)) -> IO(Endpoint.RoutedConnection):
  match progress attempted:
    case (Endpoint.Routed{conn,Endpoint.SeekingDirect{plan,Nil{},since}},Done{Endpoint.RelayRoute{}}) True{}:
      IO.pure(Endpoint.RoutedConnection,Endpoint.Routed{conn,Endpoint.SeekingDirect{plan,[],since}})
    case (Endpoint.Routed{conn,Endpoint.ValidatingDirect{plan,rest}},Done{Endpoint.RelayRoute{}}) _:
      wait_more(Endpoint.Routed{conn,Endpoint.ValidatingDirect{plan,rest}},True{},next)
    case (owner,Done{Endpoint.RelayRoute{}}) _:
      wait_more(owner,attempted,next)
    case (owner,Done{Endpoint.DirectRoute{}}) _:
      fail_routed(Endpoint.RoutedConnection,owner,1,"the blocked direct route unexpectedly validated")
    case (owner,Fail{(code,message)}) _:
      fail_routed(Endpoint.RoutedConnection,owner,code,message)

def wait_for_failed_probe(fuel: Nat, owner: Endpoint.RoutedConnection, attempted: Bool) -> IO(Endpoint.RoutedConnection):
  match fuel:
    case 0n:
      fail_routed(Endpoint.RoutedConnection,owner,1,"the direct route was not probed while relayed")
    case 1n+left:
      do IO<Endpoint.RoutedConnection>:
        progress : Endpoint.RouteStep() <- Endpoint.step_routes(owner)
        saw_failed_probe(progress,attempted,next => seen => wait_for_failed_probe(left,next,seen))

def await_direct(progress: Endpoint.RouteStep(),
    next: Endpoint.RoutedConnection -> IO(Endpoint.RoutedConnection)) -> IO(Endpoint.RoutedConnection):
  match progress:
    case (Endpoint.Routed{(conn,None{}),state},Done{Endpoint.DirectRoute{}}):
      IO.pure(Endpoint.RoutedConnection,Endpoint.Routed{(conn,None{}),state})
    case (owner,Done{Endpoint.DirectRoute{}}):
      fail_routed(Endpoint.RoutedConnection,owner,1,"the restored route did not release the relay bridge")
    case (owner,Done{Endpoint.RelayRoute{}}):
      do IO<Endpoint.RoutedConnection>:
        IO.sleep(1)
        next(owner)
    case (owner,Fail{(code,message)}):
      fail_routed(Endpoint.RoutedConnection,owner,code,message)

def wait_for_direct(fuel: Nat, owner: Endpoint.RoutedConnection) -> IO(Endpoint.RoutedConnection):
  match fuel:
    case 0n:
      fail_routed(Endpoint.RoutedConnection,owner,1,"the restored direct route did not validate")
    case 1n+left:
      do IO<Endpoint.RoutedConnection>:
        progress : Endpoint.RouteStep() <- Endpoint.step_routes(owner)
        await_direct(progress,next => wait_for_direct(left,next))

def close_cycle_relay(bridge: Maybe<&1,Relay.Bridge>) -> IO(Unit):
  match bridge:
    case None{}:
      IO.pure(Unit,Unit{})
    case Some{path}:
      IO.try(Unit,Relay.stop(path))

def finish_cycle(recovered: Endpoint.RoutedConnection, +stream: U32) -> IO(Unit):
  Endpoint.Routed{(conn,bridge),_} = recovered
  do IO<Unit>:
    IO.print("PASS relay path validated")
    finished : Quic.DatagramConnection <- send_byte(conn,stream,255,1)
    Migration.finish_stream_reply(finished,stream)
    close_cycle_relay(bridge)

def second_cut(confirmed: Endpoint.RoutedConnection & Unit, stream: U32) -> IO(Unit):
  (owner,_) = confirmed
  do IO<Unit>:
    IO.print("CUT_DIRECT")
    relayed : Endpoint.RoutedConnection <- wait_for_relay(12500n,owner)
    finish_cycle(relayed,stream)

def restore_direct(confirmed: Endpoint.RoutedConnection & Unit, +stream: U32) -> IO(Unit):
  (owner,_) = confirmed
  do IO<Unit>:
    blocked : Endpoint.RoutedConnection <- wait_for_failed_probe(11000n,owner,False{})
    IO.print("RESTORE_DIRECT")
    direct : Endpoint.RoutedConnection <- wait_for_direct(9000n,blocked)
    proven : Endpoint.RoutedConnection & Unit <-
      Endpoint.use_routed_connection(Unit,direct,c => send_and_ack(c,stream,0,16))
    second_cut(proven,stream)

def after_first_cut(owner: Endpoint.RoutedConnection, +stream: U32, restore: Bool) -> IO(Unit):
  match restore:
    case True{}:
      do IO<Unit>:
        confirmed : Endpoint.RoutedConnection & Unit <-
          Endpoint.use_routed_connection(Unit,owner,c => send_and_ack(c,stream,22,12))
        restore_direct(confirmed,stream)
    case False{}:
      finish_routed(owner,stream)

def cut_direct(primed: Endpoint.RoutedConnection & U32, restore: Bool) -> IO(Unit):
  (owner,stream) = primed
  do IO<Unit>:
    now : U32 <- Quic.quic_millis()
    healthy : Endpoint.RoutedConnection <- observe_healthy(7000n,owner,now)
    IO.print("CUT_DIRECT")
    recovered : Endpoint.RoutedConnection <- wait_for_relay(12500n,healthy)
    after_first_cut(recovered,stream,restore)

def prime_routed(conn: Quic.DatagramConnection) -> IO(Quic.DatagramConnection & U32):
  do IO<Quic.DatagramConnection & U32>:
    opened : Quic.DatagramConnection & U32 <- Fixture.poll_stream(2500n,conn,Fixture.OpenStream{0})
    Migration.prime_stream(opened)

def already_relayed(primed: Endpoint.RoutedConnection & U32) -> IO(Unit):
  (owner,stream) = primed
  after_first_cut(owner,stream,True{})

def first_dial_timeout(relay_first: Bool) -> U32:
  match relay_first:
    case True{}:
      200
    case False{}:
      3500

def start_cycle(primed: Endpoint.RoutedConnection & U32, restore: Bool, relay_first: Bool) -> IO(Unit):
  match relay_first:
    case False{}:
      cut_direct(primed,restore)
    case True{}:
      already_relayed(primed)

def recover_via_relay(url: String, host: String, port: U32, restore: Bool, +relay_first: Bool) -> IO(Unit):
  do IO<Unit>:
    owner : Endpoint.RoutedConnection <- IO.try(Endpoint.RoutedConnection,
      Endpoint.connect_routed(Endpoint.DialRoutes{[Endpoint.IpAddress{host,port}],["invalid-relay",url]},
        Endpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.public_key(False{}),Fixture.fixture_alpn()},
        Endpoint.HandshakeTimeouts{first_dial_timeout(relay_first),6000}))
    primed : Endpoint.RoutedConnection & U32 <- Endpoint.use_routed_connection(U32,owner,prime_routed)
    start_cycle(primed,restore,relay_first)

def route(url: String, host: String, port: Maybe<&2,U32>, mode: Maybe<&2,U32>) -> IO(Unit):
  match port mode:
    case Some{direct_port} Some{0}:
      do IO<Unit>:
        conn : Endpoint.Connection() <- IO.try(Endpoint.Connection(),
          Endpoint.connect_routes(Endpoint.DialRoutes{[],[url]},
            Endpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.public_key(False{}),Fixture.fixture_alpn()},
            Endpoint.HandshakeTimeouts{0,6000}))
        exercise(conn,host,direct_port)
    case Some{direct_port} Some{1}:
      dial_direct_then_relay(url,host,direct_port)
    case Some{direct_port} Some{2}:
      recover_via_relay(url,host,direct_port,False{},False{})
    case Some{direct_port} Some{3}:
      recover_via_relay(url,host,direct_port,True{},False{})
    case Some{direct_port} Some{4}:
      recover_via_relay(url,host,direct_port,True{},True{})
    case _ _:
      IO.die(Unit,2,"expected a direct peer port and a migration direction")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{url,Con{host,Con{port,Con{mode,Nil{}}}}}}:
      route(url,host,U32.read(port),U32.read(mode))
    case _:
      IO.die(Unit,2,"expected a relay URL, direct peer host, port, and direction")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
