import Base
import ../src/endpoint.bend as Endpoint
import ../src/endpoint_multipath.bend as Multipath
import ../src/quic_multipath.bend as Quic
import ../src/relay_quic.bend as Path
import ./quic_multipath_bend.bend as Fixture

def fail(-T: Type, connection: Multipath.Connection(), code: U32, message: String) -> IO(T):
  do IO<T>:
    _ : Result<&1,&1,U32 & String,Unit> <- Multipath.disconnect(connection)
    IO.die(T,code,message)

def ready_probe(result: Multipath.Connection() & Result<&1,&1,U32 & String,Maybe<&1,U32>>,
    retry: Multipath.Connection() -> IO(Multipath.Connection() & U32)) -> IO(Multipath.Connection() & U32):
  match result:
    case (owner,Done{Some{path}}):
      IO.pure(Multipath.Connection() & U32,(owner,path))
    case (owner,Done{None{}}):
      do IO<Multipath.Connection() & U32>:
        IO.sleep(1)
        retry(owner)
    case (owner,Fail{(code,message)}):
      fail(Multipath.Connection() & U32,owner,code,message)

def probe_after_step(result: Multipath.Connection() & Result<&1,&1,U32 & String,U32>,
    local: Endpoint.Address, peer: Endpoint.Address,
    retry: Multipath.Connection() -> IO(Multipath.Connection() & U32)) -> IO(Multipath.Connection() & U32):
  match result:
    case (owner,Done{2}):
      do IO<Multipath.Connection() & U32>:
        probed : Multipath.Connection() & Result<&1,&1,U32 & String,Maybe<&1,U32>> <-
          Multipath.probe_direct(owner,local,peer)
        ready_probe(probed,retry)
    case (owner,Fail{(code,message)}):
      fail(Multipath.Connection() & U32,owner,code,message)
    case (owner,_):
      fail(Multipath.Connection() & U32,owner,1,"multipath was not negotiated")

def probe(fuel: Nat, owner: Multipath.Connection(), +local: Endpoint.Address, +peer: Endpoint.Address)
    -> IO(Multipath.Connection() & U32):
  match fuel:
    case 0n:
      fail(Multipath.Connection() & U32,owner,1,"direct path probe timed out")
    case 1n+left:
      do IO<Multipath.Connection() & U32>:
        step : Multipath.Connection() & Result<&1,&1,U32 & String,U32> <-
          Multipath.use_connection(Result<&1,&1,U32 & String,U32>,owner,Quic.step_multipath)
        probe_after_step(step,local,peer,next => probe(left,next,local,peer))

def check_live(outcome: Quic.MultipathConnection & U32, bridge: Maybe<&1,Path.Bridge>) -> IO(Unit):
  match outcome:
    case (conn,1):
      do IO<Unit>:
        IO.try(Unit,Multipath.disconnect((conn,bridge)))
        IO.print("PASS endpoint exchanged datagrams and affine streams over two paths")
    case (conn,_):
      fail(Unit,(conn,bridge),1,"alternate endpoint path was unavailable")

def read_replies(sent: Quic.MultipathConnection & U32, bridge: Maybe<&1,Path.Bridge>, +path: U32, first: U32) -> IO(Unit):
  (conn,second) = sent
  do IO<Unit>:
    read_a : Quic.MultipathConnection <- Fixture.receive(4000n,conn,first,11,False{})
    read_b : Quic.MultipathConnection <- Fixture.receive(4000n,read_a,second,22,False{})
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.multipath_status(read_b,path)
    live : Quic.MultipathConnection & U32 <- Fixture.ok(U32,result)
    check_live(live,bridge)

def send_second(sent: Quic.MultipathConnection & U32, bridge: Maybe<&1,Path.Bridge>, +path: U32) -> IO(Unit):
  (conn,first) = sent
  do IO<Unit>:
    opened : Quic.MultipathConnection & U32 <- Fixture.open(conn)
    sent_b : Quic.MultipathConnection & U32 <- Fixture.send(opened,path,22)
    read_replies(sent_b,bridge,path,first)

def exchange(conn: Quic.MultipathConnection, bridge: Maybe<&1,Path.Bridge>, +path: U32) -> IO(Unit):
  do IO<Unit>:
    validated : Quic.MultipathConnection <- Fixture.wait_path(4000n,conn,path)
    datagrams : Quic.MultipathConnection <- Fixture.datagram_exchange(validated)
    opened : Quic.MultipathConnection & U32 <- Fixture.open(datagrams)
    sent : Quic.MultipathConnection & U32 <- Fixture.send(opened,0,11)
    send_second(sent,bridge,path)

def exchange_on(candidate: Multipath.Connection() & U32) -> IO(Unit):
  ((conn,bridge),path) = candidate
  exchange(conn,bridge,path)

def exercise_paths(owner: Multipath.Connection(), +host: String, port: U32) -> IO(Unit):
  do IO<Unit>:
    added : Multipath.Connection() & U32 <- probe(4000n,owner,Endpoint.IpAddress{host,0},Endpoint.IpAddress{host,port})
    exchange_on(added)

def check_route(owner: Multipath.Connection(), fallback: Bool, host: String, port: U32) -> IO(Unit):
  match owner fallback:
    case (conn,Some{bridge}) True{}:
      do IO<Unit>:
        IO.print("PASS endpoint fell back to the relay")
        exercise_paths((conn,Some{bridge}),host,port)
    case (conn,None{}) False{}:
      do IO<Unit>:
        IO.print("PASS endpoint dialed the direct route")
        exercise_paths((conn,None{}),host,port)
    case route _:
      fail(Unit,route,1,"endpoint chose the wrong initial route")

def test_direct_timeout(fallback: Bool) -> U32:
  match fallback:
    case True{}:
      150
    case False{}:
      2000

def dial_with_alpn(routes: Endpoint.Routes, +fallback: Bool, host: String, port: U32, alpn: List<&2,U32>) -> IO(Unit):
  do IO<Unit>:
    owner : Multipath.Connection() <- IO.try(Multipath.Connection(),
      Multipath.connect_routes(routes,
        Endpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.fixture_key(0),alpn},
        Endpoint.HandshakeTimeouts{test_direct_timeout(fallback),6000}))
    check_route(owner,fallback,host,port)

def fixture_alpn() -> List<&2,U32>:
  [105,114,111,104,45,98,101,110,100,47,99,111,109,112,97,116,47,49]

def direct(+host: String, direct_port: Maybe<&2,U32>, alpn: List<&2,U32>) -> IO(Unit):
  match direct_port:
    case Some{+port}:
      dial_with_alpn(Endpoint.DialRoutes{[Endpoint.IpAddress{host,port}],[]},False{},host,port,alpn)
    case None{}:
      IO.die(Unit,2,"expected the Iroh direct port")

def relayed(+host: String, direct_port: Maybe<&2,U32>, dropped_port: Maybe<&2,U32>, url: String) -> IO(Unit):
  match direct_port dropped_port:
    case Some{port} Some{blackhole}:
      dial_with_alpn(Endpoint.DialRoutes{[Endpoint.IpAddress{host,blackhole}],[url]},True{},host,port,fixture_alpn())
    case _ _:
      IO.die(Unit,2,"expected both UDP ports")

def routed_fail(-T: Type, owner: Multipath.RoutedConnection, code: U32, message: String) -> IO(T):
  do IO<T>:
    _ : Result<&1,&1,U32 & String,Unit> <- Multipath.close_routes(owner)
    IO.die(T,code,message)

def await_promotion(progress: Multipath.RoutedConnection & Multipath.PathResult(),
    retry: Multipath.RoutedConnection -> IO(Multipath.RoutedConnection)) -> IO(Multipath.RoutedConnection):
  match progress:
    case (owner,Done{Multipath.PromotedPath{_}}):
      IO.pure(Multipath.RoutedConnection,owner)
    case (owner,Done{Multipath.InitialPath{}}):
      do IO<Multipath.RoutedConnection>:
        IO.sleep(1)
        retry(owner)
    case (owner,Done{Multipath.RecoveredRelay{_}}):
      routed_fail(Multipath.RoutedConnection,owner,1,"relay appeared while waiting for a direct path")
    case (owner,Fail{(code,message)}):
      routed_fail(Multipath.RoutedConnection,owner,code,message)

def wait_promotion(fuel: Nat, owner: Multipath.RoutedConnection) -> IO(Multipath.RoutedConnection):
  match fuel:
    case 0n:
      routed_fail(Multipath.RoutedConnection,owner,1,"direct path did not become preferred")
    case 1n+left:
      do IO<Multipath.RoutedConnection>:
        progress : Multipath.RoutedConnection & Multipath.PathResult() <- Multipath.step_routes(owner)
        await_promotion(progress,next => wait_promotion(left,next))

def datagrams_on_relay(conn: Quic.MultipathConnection) -> IO(Quic.MultipathConnection & Unit):
  do IO<Quic.MultipathConnection & Unit>:
    next : Quic.MultipathConnection <- Fixture.datagram_exchange(conn)
    return (next,Unit{})

def write_unpinned(opened: Quic.MultipathConnection & U32, byte: U32) -> IO(Quic.MultipathConnection & U32):
  (conn,stream) = opened
  Fixture.write_assigned((conn,Unit{}),stream,byte)

def send_unpinned(conn: Quic.MultipathConnection, byte: U32) -> IO(Quic.MultipathConnection & U32):
  do IO<Quic.MultipathConnection & U32>:
    opened : Quic.MultipathConnection & U32 <- Fixture.open(conn)
    write_unpinned(opened,byte)

def read_routed(sent: Multipath.RoutedConnection & U32, first: U32) -> IO(Unit):
  (owner,second) = sent
  Multipath.Routed{(conn,bridge),_,_} = owner
  do IO<Unit>:
    read_a : Quic.MultipathConnection <- Fixture.receive(4000n,conn,first,11,False{})
    read_b : Quic.MultipathConnection <- Fixture.receive(4000n,read_a,second,22,False{})
    IO.try(Unit,Multipath.disconnect((read_b,bridge)))
    IO.print("PASS routed endpoint promoted the direct path")

def held_route(result: Multipath.RoutedConnection & Multipath.PathResult(),
    retry: Multipath.RoutedConnection -> IO(Multipath.RoutedConnection)) -> IO(Multipath.RoutedConnection):
  match result:
    case (owner,Done{Multipath.PromotedPath{_}}):
      do IO<Multipath.RoutedConnection>:
        IO.sleep(1)
        retry(owner)
    case (owner,_):
      routed_fail(Multipath.RoutedConnection,owner,1,"the direct path stopped during address refresh")

def hold_tick(owner: Multipath.RoutedConnection, finished: Bool,
    retry: Multipath.RoutedConnection -> IO(Multipath.RoutedConnection)) -> IO(Multipath.RoutedConnection):
  match finished:
    case True{}:
      IO.pure(Multipath.RoutedConnection,owner)
    case False{}:
      do IO<Multipath.RoutedConnection>:
        result : Multipath.RoutedConnection & Multipath.PathResult() <- Multipath.step_routes(owner)
        held_route(result,retry)

def hold_until(fuel: Nat, owner: Multipath.RoutedConnection, +start: U32, +interval: U32, now: U32)
    -> IO(Multipath.RoutedConnection):
  match fuel:
    case 0n:
      routed_fail(Multipath.RoutedConnection,owner,1,"address refresh wait exhausted")
    case 1n+left:
      hold_tick(owner,U32.is_ge(U32.sub(now,start),interval),next =>
        do IO<Multipath.RoutedConnection>:
          current : U32 <- Quic.multipath_millis()
          hold_until(left,next,start,interval,current))

def hold_sent(sent: Multipath.RoutedConnection & U32, first: U32, interval: U32) -> IO(Unit):
  (owner,second) = sent
  do IO<Unit>:
    +now : U32 <- Quic.multipath_millis()
    active : Multipath.RoutedConnection <- hold_until(36000n,owner,now,interval,now)
    read_routed((active,second),first)

def promote_routed(initial: Multipath.RoutedConnection & U32, interval: U32) -> IO(Unit):
  (relay_sent,first) = initial
  do IO<Unit>:
    IO.print("ENABLE_DIRECT")
    promoted : Multipath.RoutedConnection <- wait_promotion(5000n,relay_sent)
    probed : Multipath.RoutedConnection & U32 <-
      Multipath.use_routed_connection(U32,promoted,c => send_unpinned(c,22))
    hold_sent(probed,first,interval)

def send_first_routed(exchanged: Multipath.RoutedConnection & Unit, interval: U32) -> IO(Unit):
  (relay_ready,_) = exchanged
  do IO<Unit>:
    initial : Multipath.RoutedConnection & U32 <-
      Multipath.use_routed_connection(U32,relay_ready,c => send_unpinned(c,11))
    promote_routed(initial,interval)

def exchange_routed(owner: Multipath.RoutedConnection, interval: U32) -> IO(Unit):
  do IO<Unit>:
    exchanged : Multipath.RoutedConnection & Unit <-
      Multipath.use_routed_connection(Unit,owner,datagrams_on_relay)
    send_first_routed(exchanged,interval)

def route_exchange(routes: Endpoint.Routes, interval: U32) -> IO(Unit):
  do IO<Unit>:
    owner : Multipath.RoutedConnection <- IO.try(Multipath.RoutedConnection,
      Multipath.connect_routed(routes,
        Endpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.fixture_key(0),fixture_alpn()},
        Endpoint.HandshakeTimeouts{150,6000}))
    exchange_routed(owner,interval)

def test_candidates(+host: String, blocked: Maybe<&2,U32>, gated: Maybe<&2,U32>)
    -> Maybe<&2,List<&2,Endpoint.Address>>:
  match blocked gated:
    case Some{0} Some{0}:
      Some{[]}
    case Some{blackhole} Some{reachable}:
      Some{[Endpoint.IpAddress{host,blackhole},Endpoint.IpAddress{host,reachable}]}
    case _ _:
      None{}

def auto(candidates: Maybe<&2,List<&2,Endpoint.Address>>, url: String, interval: U32) -> IO(Unit):
  match candidates:
    case Some{ips}:
      route_exchange(Endpoint.DialRoutes{ips,[url]},interval)
    case None{}:
      IO.die(Unit,2,"expected both candidate ports")

def hold_interval(mode: String) -> U32:
  match mode:
    case "qad-refresh":
      27000
    case _:
      0

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,+host,blackhole,gated,url,"auto"]:
      auto(test_candidates(host,U32.read(blackhole),U32.read(gated)),url,hold_interval(host))
    case [_,host,port,"binary"]:
      direct(host,U32.read(port),Fixture.binary_alpn())
    case Con{_,Con{host,Con{port,Nil{}}}}:
      direct(host,U32.read(port),fixture_alpn())
    case Con{_,Con{host,Con{port,Con{blackhole,Con{url,Nil{}}}}}}:
      relayed(host,U32.read(port),U32.read(blackhole),url)
    case _:
      IO.die(Unit,2,"expected a peer address and optional relay route")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
