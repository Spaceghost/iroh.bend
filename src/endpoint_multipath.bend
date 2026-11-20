import Base
import ./endpoint.bend as Endpoint
import ./quic_multipath.bend as Quic
import ./relay_quic.bend as Relay

def Connection() -> Type:
  Endpoint.Transport(Quic.MultipathConnection)

def ConnectResult() -> Type:
  Endpoint.TransportResult(Quic.MultipathConnection)

def dial(address: Endpoint.Address, identity: Endpoint.Identity, timeout: U32) -> IO(Quic.ConnectResult()):
  Endpoint.IpAddress{host,port} = address
  Endpoint.PeerKeys{seed,peer,alpn} = identity
  Quic.connect_multipath_bytes(host,port,seed,peer,alpn,U32.to_nat(timeout))

def connect_routes(routes: Endpoint.Routes, identity: Endpoint.Identity, timeouts: Endpoint.Timeouts)
    -> IO(ConnectResult()):
  Endpoint.dial_plan(~Quic.MultipathConnection,~dial,routes,identity,timeouts)

def lookup_and_connect(+identity: Endpoint.Identity, resolver: Endpoint.DnsSource, timeouts: Endpoint.Timeouts)
    -> IO(ConnectResult()):
  do IO<ConnectResult()>:
    routes : Result<&1,&1,U32 & String,Endpoint.Routes> <- Endpoint.lookup_routes(identity,resolver)
    Endpoint.connect_resolved(~Quic.MultipathConnection,~dial,routes,identity,timeouts)

def verify_and_connect(+identity: Endpoint.Identity, packet: List<&2,U32>, timeouts: Endpoint.Timeouts)
    -> IO(ConnectResult()):
  do IO<ConnectResult()>:
    routes : Result<&1,&1,U32 & String,Endpoint.Routes> <- Endpoint.verify_routes(identity,packet)
    Endpoint.connect_resolved(~Quic.MultipathConnection,~dial,routes,identity,timeouts)

def keep_relay(-R: Type, outcome: Quic.MultipathConnection & R, bridge: Maybe<&1,Relay.Bridge>) -> Connection() & R:
  (conn,value) = outcome
  ((conn,bridge),value)

# Drive the QUIC connection while retaining its optional relay bridge.
def use_connection(-R: Type, connection: Connection(),
    operation: Quic.MultipathConnection -> IO(Quic.MultipathConnection & R)) -> IO(Connection() & R):
  (conn,bridge) = connection
  do IO<Connection() & R>:
    outcome : Quic.MultipathConnection & R <- operation(conn)
    return keep_relay(R,outcome,bridge)

# Open a direct path on the existing connection. Keep any relay path available.
def probe_direct(connection: Connection(), local: Endpoint.Address, peer: Endpoint.Address)
    -> IO(Connection() & Result<&1,&1,U32 & String,Maybe<&1,U32>>):
  Endpoint.IpAddress{source,source_port} = local
  Endpoint.IpAddress{target,target_port} = peer
  use_connection(Result<&1,&1,U32 & String,Maybe<&1,U32>>,connection,
    conn => Quic.probe_multipath(conn,source,source_port,target,target_port))

def stop_bridge(bridge: Maybe<&1,Relay.Bridge>) -> IO(Result<&1,&1,U32 & String,Unit>):
  match bridge:
    case Some{relay}:
      Relay.stop(relay)
    case None{}:
      IO.pure(Result<&1,&1,U32 & String,Unit>,Done{Unit{}})

def disconnect(connection: Connection()) -> IO(Result<&1,&1,U32 & String,Unit>):
  (conn,bridge) = connection
  do IO<Result<&1,&1,U32 & String,Unit>>:
    Quic.close_multipath(conn)
    stop_bridge(bridge)

type ProbeState is Data:
  Disabled{}
  Seeking{remaining: List<&2,Endpoint.Address>, since: U32}
  Validating{remaining: List<&2,Endpoint.Address>, path: U32, since: U32}
  DirectPath{path: U32}
  Waiting{since: U32}

type RoutedConnection is Type:
  Routed{transport: Connection(), candidates: List<&2,Endpoint.Address>, state: ProbeState}

type SelectedPath is Data:
  InitialPath{}
  PromotedPath{id: U32}

def RoutedResult() -> Type:
  Result<&1,&1,U32 & String,RoutedConnection>

def PathResult() -> Type:
  Result<&1,&1,U32 & String,SelectedPath>

def route_state(base: Connection(), +candidates: List<&2,Endpoint.Address>, now: U32) -> RoutedConnection:
  match base:
    case (conn,Some{bridge}):
      Routed{(conn,Some{bridge}),candidates,Seeking{candidates,now}}
    case (conn,None{}):
      Routed{(conn,None{}),[],Disabled{}}

def connect_routed(+routes: Endpoint.Routes, identity: Endpoint.Identity, timeouts: Endpoint.Timeouts)
    -> IO(RoutedResult()):
  Endpoint.DialRoutes{candidates,_} = routes
  do IO<RoutedResult()>:
    result : ConnectResult() <- connect_routes(routes,identity,timeouts)
    now : U32 <- Quic.multipath_millis()
    return Result.map(&1,&1,U32 & String,Connection(),RoutedConnection,
      conn => route_state(conn,candidates,now),result)

def after_probe(outcome: Connection() & Result<&1,&1,U32 & String,Maybe<&1,U32>>, peer: Endpoint.Address,
    rest: List<&2,Endpoint.Address>, since: U32, now: U32, expired: Bool) -> Connection() & ProbeState:
  match outcome expired:
    case (conn,Done{Some{path}}) _:
      (conn,Validating{rest,path,now})
    case (conn,Done{None{}}) False{}:
      (conn,Seeking{Con{peer,rest},since})
    case (conn,_) _:
      (conn,Seeking{rest,now})

def seek(conn: Connection(), peers: List<&2,Endpoint.Address>, +since: U32, +now: U32)
    -> IO(Connection() & ProbeState):
  match peers:
    case Nil{}:
      IO.pure(Connection() & ProbeState,(conn,Waiting{now}))
    case Con{+peer,rest}:
      do IO<Connection() & ProbeState>:
        probe : Connection() & Result<&1,&1,U32 & String,Maybe<&1,U32>> <-
          probe_direct(conn,Endpoint.IpAddress{"",0},peer)
        return after_probe(probe,peer,rest,since,now,U32.is_ge(U32.sub(now,since),1000))

def check_path(conn: Connection(), path: U32) -> IO(Connection() & Result<&1,&1,U32 & String,U32>):
  use_connection(Result<&1,&1,U32 & String,U32>,conn,c => Quic.multipath_status(c,path))

def standby(conn: Connection(), value: U32) -> IO(Connection() & Result<&1,&1,U32 & String,Unit>):
  use_connection(Result<&1,&1,U32 & String,Unit>,conn,c => Quic.set_multipath_standby(c,0,value))

def without_status(pair: Connection() & Result<&1,&1,U32 & String,Unit>) -> Connection():
  (conn,_) = pair
  conn

def retire(conn: Connection(), path: U32) -> IO(Connection()):
  do IO<Connection()>:
    result : Connection() & Result<&1,&1,U32 & String,Unit> <-
      use_connection(Result<&1,&1,U32 & String,Unit>,conn,c => Quic.retire_multipath_path(c,path))
    return without_status(result)

def promote(outcome: Connection() & Result<&1,&1,U32 & String,Unit>, path: U32,
    rest: List<&2,Endpoint.Address>, now: U32) -> Connection() & ProbeState:
  match outcome:
    case (conn,Done{_}):
      (conn,DirectPath{path})
    case (conn,Fail{_}):
      (conn,Validating{rest,path,now})

def settle_alternate(outcome: Connection() & Result<&1,&1,U32 & String,Unit>,
    rest: List<&2,Endpoint.Address>, +path: U32, now: U32) -> IO(Connection() & ProbeState):
  match outcome:
    case (conn,Done{_}):
      IO.pure(Connection() & ProbeState,(conn,Validating{rest,path,now}))
    case (conn,Fail{_}):
      do IO<Connection() & ProbeState>:
        kept : Connection() <- retire(conn,path)
        return (kept,Seeking{rest,now})

def alternate(conn: Connection(), remaining: List<&2,Endpoint.Address>, +path: U32, now: U32)
    -> IO(Connection() & ProbeState):
  match remaining:
    case Con{Endpoint.IpAddress{host,port},rest}:
      do IO<Connection() & ProbeState>:
        result : Connection() & Result<&1,&1,U32 & String,Unit> <-
          use_connection(Result<&1,&1,U32 & String,Unit>,conn,c => Quic.probe_multipath_alternate(c,path,host,port))
        settle_alternate(result,rest,path,now)
    case Nil{}:
      do IO<Connection() & ProbeState>:
        kept : Connection() <- retire(conn,path)
        return (kept,Waiting{now})

def validation_wait(peers: List<&2,Endpoint.Address>) -> U32:
  match peers:
    case Con{_,_}:
      250
    case Nil{}:
      1000

def finish_check(outcome: Connection() & Result<&1,&1,U32 & String,U32>, rest: List<&2,Endpoint.Address>,
    +path: U32, since: U32, now: U32, expired: Bool) -> IO(Connection() & ProbeState):
  match outcome expired:
    case (conn,Done{1}) _:
      do IO<Connection() & ProbeState>:
        preferred : Connection() & Result<&1,&1,U32 & String,Unit> <- standby(conn,1)
        return promote(preferred,path,rest,now)
    case (conn,Done{0}) False{}:
      IO.pure(Connection() & ProbeState,(conn,Validating{rest,path,since}))
    case (conn,Done{0}) True{}:
      alternate(conn,rest,path,now)
    case (conn,_) _:
      do IO<Connection() & ProbeState>:
        kept : Connection() <- retire(conn,path)
        return (kept,Seeking{rest,now})

def keep_direct(outcome: Connection() & Result<&1,&1,U32 & String,U32>, +path: U32,
    now: U32) -> IO(Connection() & ProbeState):
  match outcome:
    case (conn,Done{1}):
      IO.pure(Connection() & ProbeState,(conn,DirectPath{path}))
    case (conn,_):
      do IO<Connection() & ProbeState>:
        relay : Connection() & Result<&1,&1,U32 & String,Unit> <- standby(conn,0)
        kept : Connection() <- retire(without_status(relay),path)
        return (kept,Waiting{now})

def retry_routes(conn: Connection(), candidates: List<&2,Endpoint.Address>, since: U32,
    +now: U32, elapsed: Bool) -> IO(Connection() & ProbeState):
  match elapsed:
    case True{}:
      seek(conn,candidates,now,now)
    case False{}:
      IO.pure(Connection() & ProbeState,(conn,Waiting{since}))

def advance(conn: Connection(), candidates: List<&2,Endpoint.Address>, state: ProbeState, +now: U32)
    -> IO(Connection() & ProbeState):
  match state:
    case Disabled{}:
      IO.pure(Connection() & ProbeState,(conn,Disabled{}))
    case Seeking{rest,since}:
      seek(conn,rest,since,now)
    case Validating{+rest,+path,+since}:
      do IO<Connection() & ProbeState>:
        status : Connection() & Result<&1,&1,U32 & String,U32> <- check_path(conn,path)
        finish_check(status,rest,path,since,now,U32.is_ge(U32.sub(now,since),validation_wait(rest)))
    case DirectPath{+path}:
      do IO<Connection() & ProbeState>:
        status : Connection() & Result<&1,&1,U32 & String,U32> <- check_path(conn,path)
        keep_direct(status,path,now)
    case Waiting{+since}:
      retry_routes(conn,candidates,since,now,U32.is_ge(U32.sub(now,since),1000))

def selected(state: ProbeState) -> SelectedPath:
  match state:
    case DirectPath{id}:
      PromotedPath{id}
    case _:
      InitialPath{}

def route_progress(progress: Connection() & ProbeState, candidates: List<&2,Endpoint.Address>)
    -> RoutedConnection & PathResult():
  (conn,+current) = progress
  (Routed{conn,candidates,current},Done{selected(current)})

def advance_routes(outcome: Connection() & Result<&1,&1,U32 & String,U32>, +candidates: List<&2,Endpoint.Address>,
    state: ProbeState) -> IO(RoutedConnection & PathResult()):
  match outcome:
    case (conn,Done{2}):
      do IO<RoutedConnection & PathResult()>:
        now : U32 <- Quic.multipath_millis()
        progress : Connection() & ProbeState <- advance(conn,candidates,state,now)
        return route_progress(progress,candidates)
    case (conn,Done{_}):
      IO.pure(RoutedConnection & PathResult(),(Routed{conn,candidates,state},Done{InitialPath{}}))
    case (conn,Fail{error}):
      IO.pure(RoutedConnection & PathResult(),(Routed{conn,candidates,state},Fail{error}))

# Drive QUIC and retry published direct addresses while keeping the relay alive.
def step_routes(owner: RoutedConnection) -> IO(RoutedConnection & PathResult()):
  Routed{conn,candidates,state} = owner
  do IO<RoutedConnection & PathResult()>:
    result : Connection() & Result<&1,&1,U32 & String,U32> <-
      use_connection(Result<&1,&1,U32 & String,U32>,conn,Quic.step_multipath)
    advance_routes(result,candidates,state)

def keep_routes(-R: Type, result: Connection() & R, candidates: List<&2,Endpoint.Address>, state: ProbeState)
    -> RoutedConnection & R:
  (next,value) = result
  (Routed{next,candidates,state},value)

def use_routed_connection(-R: Type, owner: RoutedConnection,
    operation: Quic.MultipathConnection -> IO(Quic.MultipathConnection & R)) -> IO(RoutedConnection & R):
  Routed{conn,candidates,state} = owner
  do IO<RoutedConnection & R>:
    result : Connection() & R <- use_connection(R,conn,operation)
    return keep_routes(R,result,candidates,state)

def close_routes(owner: RoutedConnection) -> IO(Result<&1,&1,U32 & String,Unit>):
  Routed{conn,_,_} = owner
  disconnect(conn)
