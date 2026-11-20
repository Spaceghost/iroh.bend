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

def dial(routes: Endpoint.Routes, fallback: Bool, host: String, port: U32) -> IO(Unit):
  do IO<Unit>:
    owner : Multipath.Connection() <- IO.try(Multipath.Connection(),
      Multipath.connect_routes(routes,
        Endpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.fixture_key(0),
          [105,114,111,104,45,98,101,110,100,47,99,111,109,112,97,116,47,49]},
        Endpoint.HandshakeTimeouts{150,6000}))
    check_route(owner,fallback,host,port)

def direct(+host: String, direct_port: Maybe<&2,U32>) -> IO(Unit):
  match direct_port:
    case Some{+port}:
      dial(Endpoint.DialRoutes{[Endpoint.IpAddress{host,port}],[]},False{},host,port)
    case None{}:
      IO.die(Unit,2,"expected the Iroh direct port")

def relayed(+host: String, direct_port: Maybe<&2,U32>, dropped_port: Maybe<&2,U32>, url: String) -> IO(Unit):
  match direct_port dropped_port:
    case Some{port} Some{blackhole}:
      dial(Endpoint.DialRoutes{[Endpoint.IpAddress{host,blackhole}],[url]},True{},host,port)
    case _ _:
      IO.die(Unit,2,"expected both UDP ports")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{host,Con{port,Nil{}}}}:
      direct(host,U32.read(port))
    case Con{_,Con{host,Con{port,Con{blackhole,Con{url,Nil{}}}}}}:
      relayed(host,U32.read(port),U32.read(blackhole),url)
    case _:
      IO.die(Unit,2,"expected a peer address and optional relay route")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
