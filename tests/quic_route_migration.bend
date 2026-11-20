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
