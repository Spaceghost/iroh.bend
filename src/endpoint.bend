import Base
import ./direct.bend as Direct
import ./discovery.bend as Dns
import ./pkarr.bend as Pkarr
import ./relay_quic.bend as Path
import ./quic_datagram.bend as Quic

type Address is Data:
  IpAddress{host: String, port: U32}

type Routes is Data:
  DialRoutes{direct: List<&2,Address>, relays: List<&2,String>}

type Identity is Data:
  PeerKeys{local_seed: List<&2,U32>, endpoint_id: List<&2,U32>, alpn: List<&2,U32>}

type Timeouts is Data:
  HandshakeTimeouts{direct_ms: U32, relay_ms: U32}

type DnsSource is Data:
  DnsResolver{origin: String, host: String, port: U32, timeout_ms: U32}

def Connected() -> Type:
  Direct.QuicConnection & Maybe<&1,Path.Bridge>

def Outcome() -> Type:
  Result<&1,&1,U32 & String,Connected()>

def Transport(-C: Type) -> Type:
  C & Maybe<&1,Path.Bridge>

def TransportResult(-C: Type) -> Type:
  Result<&1,&1,U32 & String,Transport(C)>

def Dialer(-C: Type) -> Type:
  Address -> Identity -> U32 -> IO(Result<&1,&1,U32 & String,C>)

def Connection() -> Type:
  Transport(Quic.DatagramConnection)

def ConnectResult() -> Type:
  TransportResult(Quic.DatagramConnection)

def ascii(bytes: List<&2,U32>) -> Bool:
  match bytes:
    case Nil{}:
      True{}
    case Con{+b,rest}:
      U32.is_ge(b,33) && U32.is_le(b,126) && ascii(rest)

def as_chars(bytes: List<&2,U32>) -> List<&2,Char>:
  match bytes:
    case Nil{}:
      []
    case Con{b,rest}:
      Con{Char.from_u32(b),as_chars(rest)}

def ip_result(host: String, port: U32, valid: Bool) -> Maybe<&2,Address>:
  match valid:
    case True{}:
      Some{IpAddress{host,port}}
    case False{}:
      None{}

def ip_port(+host: String, port: Maybe<&2,U32>) -> Maybe<&2,Address>:
  match port:
    case Some{+n}:
      ip_result(host,n,Bool.not(String.is_empty(host)) && U32.is_gt(n,0) && U32.is_le(n,65535))
    case None{}:
      None{}

def ipv4(parts: List<&2,String>) -> Maybe<&2,Address>:
  match parts:
    case [host,port]:
      ip_port(host,U32.read(port))
    case _:
      None{}

def ipv6_end(host: String, port: String, valid: Bool) -> Maybe<&2,Address>:
  match valid:
    case True{}:
      ip_port(String.drop(host,1n),U32.read(String.drop(port,1n)))
    case False{}:
      None{}

def ipv6(parts: List<&2,String>) -> Maybe<&2,Address>:
  match parts:
    case [host,+port]:
      ipv6_end(host,port,String.starts_with(port,":"))
    case _:
      None{}

def ip_text(text: String, bracketed: Bool) -> Maybe<&2,Address>:
  match bracketed:
    case True{}:
      ipv6(String.split(text,']'))
    case False{}:
      ipv4(String.split(text,':'))

def decoded_ip(bytes: List<&2,U32>, valid: Bool) -> Maybe<&2,Address>:
  match valid:
    case True{}:
      +text = String.from_list(as_chars(bytes))
      ip_text(text,String.starts_with(text,"["))
    case False{}:
      None{}

def address(+bytes: List<&2,U32>) -> Maybe<&2,Address>:
  decoded_ip(bytes,ascii(bytes))

def without_suffix(bytes: List<&2,U32>) -> List<&2,U32>:
  match bytes:
    case Con{63,_}:
      []
    case Con{35,_}:
      []
    case Con{byte,rest}:
      Con{byte,without_suffix(rest)}
    case Nil{}:
      []

def relay_segments(parts: List<&2,String>) -> List<&2,String>:
  match parts:
    case Nil{}:
      ["relay"]
    case Con{_,Nil{}}:
      ["relay"]
    case Con{head,tail}:
      Con{head,relay_segments(tail)}

def relay_parts(parts: List<&2,String>, scheme: String) -> Maybe<&2,String>:
  match parts:
    case Con{SNil{},_}:
      None{}
    case Con{authority,dirs}:
      Some{scheme ++ String.join(Con{authority,relay_segments(dirs)},"/")}
    case Nil{}:
      None{}

def relay_base(rest: String, scheme: String) -> Maybe<&2,String>:
  relay_parts(String.split(rest,'/'),scheme)

def websocket_url(text: String, http: Bool, https: Bool, ws: Bool, wss: Bool) -> Maybe<&2,String>:
  match http https ws wss:
    case True{} _ _ _:
      relay_base(String.drop(text,7n),"ws://")
    case _ True{} _ _:
      relay_base(String.drop(text,8n),"wss://")
    case _ _ True{} _:
      relay_base(String.drop(text,5n),"ws://")
    case _ _ _ True{}:
      relay_base(String.drop(text,6n),"wss://")
    case _ _ _ _:
      None{}

def decoded_relay(bytes: List<&2,U32>, valid: Bool) -> Maybe<&2,String>:
  match valid:
    case True{}:
      +text = String.from_list(as_chars(without_suffix(bytes)))
      websocket_url(text,String.starts_with(text,"http://"),String.starts_with(text,"https://"),
        String.starts_with(text,"ws://"),String.starts_with(text,"wss://"))
    case False{}:
      None{}

def relay_url(+bytes: List<&2,U32>) -> Maybe<&2,String>:
  decoded_relay(bytes,ascii(bytes))

def add_ip(candidate: Maybe<&2,Address>, routes: Routes) -> Routes:
  match candidate routes:
    case Some{ip} DialRoutes{ips,relays}:
      DialRoutes{Con{ip,ips},relays}
    case _ _:
      routes

def add_relay(candidate: Maybe<&2,String>, routes: Routes) -> Routes:
  match candidate routes:
    case Some{url} DialRoutes{ips,urls}:
      DialRoutes{ips,Con{url,urls}}
    case _ _:
      routes

def routes(records: List<&2,Dns.Attribute>) -> Routes:
  match records:
    case Con{Dns.Address{value},rest}:
      add_ip(address(value),routes(rest))
    case Con{Dns.RelayUrl{value},rest}:
      add_relay(relay_url(value),routes(rest))
    case Con{Dns.UserData{_},rest}:
      routes(rest)
    case Nil{}:
      DialRoutes{[],[]}

def direct_stream(address: Address, identity: Identity, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Direct.QuicConnection>):
  IpAddress{host,port} = address
  PeerKeys{seed,peer,alpn} = identity
  Direct.quic_connect_with_timeout(host,port,seed,peer,alpn,ms)

def direct_quic(address: Address, identity: Identity, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Quic.DatagramConnection>):
  IpAddress{host,port} = address
  PeerKeys{seed,peer,alpn} = identity
  Quic.connect(host,port,seed,peer,alpn,U32.to_nat(ms))

def attach_connection(-C: Type, outcome: Result<&1,&1,U32 & String,C>, bridge: Path.Bridge)
    -> IO(TransportResult(C)):
  match outcome:
    case Done{conn}:
      IO.pure(TransportResult(C),Done{(conn,Some{bridge})})
    case Fail{error}:
      do IO<TransportResult(C)>:
        _ : Result<&1,&1,U32 & String,Unit> <- Path.stop(bridge)
        return Fail{error}

def connect_bridge(~C: Type, ~attempt: Dialer(C), outcome: Result<&1,&1,U32 & String,Path.Bridge & U32>,
    identity: Identity, ms: U32) -> IO(TransportResult(C)):
  match outcome:
    case Done{(bridge,port)}:
      do IO<TransportResult(C)>:
        result : Result<&1,&1,U32 & String,C> <- attempt(IpAddress{"127.0.0.1",port},identity,ms)
        attach_connection(C,result,bridge)
    case Fail{error}:
      IO.pure(TransportResult(C),Fail{error})

def try_relay(~C: Type, ~attempt: Dialer(C), url: String, +identity: Identity, ms: U32) -> IO(TransportResult(C)):
  PeerKeys{seed,peer,_} = identity
  do IO<TransportResult(C)>:
    path : Result<&1,&1,U32 & String,Path.Bridge & U32> <- Path.start(url,seed,peer,0)
    connect_bridge(~C,~attempt,path,identity,ms)

def continue_dial(-C: Type, outcome: TransportResult(C), next: (U32 & String) -> IO(TransportResult(C)))
    -> IO(TransportResult(C)):
  match outcome:
    case Done{conn}:
      IO.pure(TransportResult(C),Done{conn})
    case Fail{error}:
      next(error)

def try_relays(~C: Type, ~attempt: Dialer(C), urls: List<&2,String>, +identity: Identity, +ms: U32,
    last: U32 & String) -> IO(TransportResult(C)):
  match urls:
    case Nil{}:
      IO.pure(TransportResult(C),Fail{last})
    case Con{url,rest}:
      do IO<TransportResult(C)>:
        outcome : TransportResult(C) <- try_relay(~C,~attempt,url,identity,ms)
        continue_dial(C,outcome,error => try_relays(~C,~attempt,rest,identity,ms,error))

def direct_timeout(timeouts: Timeouts) -> U32:
  HandshakeTimeouts{ms,_} = timeouts
  ms

def try_ips(~C: Type, ~attempt: Dialer(C), ips: List<&2,Address>, urls: List<&2,String>, +identity: Identity,
    +timeouts: Timeouts, last: U32 & String) -> IO(TransportResult(C)):
  match ips:
    case Nil{}:
      HandshakeTimeouts{_,relay_ms} = timeouts
      try_relays(~C,~attempt,urls,identity,relay_ms,last)
    case Con{ip,rest}:
      do IO<TransportResult(C)>:
        conn : Result<&1,&1,U32 & String,C> <- attempt(ip,identity,direct_timeout(timeouts))
        continue_dial(C,Result.map(&1,&1,U32 & String,C,Transport(C),c => (c,None{}),conn),
          error => try_ips(~C,~attempt,rest,urls,identity,timeouts,error))

def dial_plan(~C: Type, ~attempt: Dialer(C), plan: Routes, identity: Identity, timeouts: Timeouts)
    -> IO(TransportResult(C)):
  DialRoutes{ips,urls} = plan
  try_ips(~C,~attempt,ips,urls,identity,timeouts,(1,"endpoint has no usable direct address or relay"))

def dial_routes(plan: Routes, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  dial_plan(~Direct.QuicConnection,~direct_stream,plan,identity,timeouts)

def dial(records: List<&2,Dns.Attribute>, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  dial_routes(routes(records),identity,timeouts)

# Try each published direct address before opening a relay path. The returned
# QUIC connection exposes both streams and application datagrams.
def connect_routes(plan: Routes, identity: Identity, timeouts: Timeouts) -> IO(ConnectResult()):
  dial_plan(~Quic.DatagramConnection,~direct_quic,plan,identity,timeouts)

def connect(records: List<&2,Dns.Attribute>, identity: Identity, timeouts: Timeouts) -> IO(ConnectResult()):
  connect_routes(routes(records),identity,timeouts)

def dns_routes(reply: Result<&1,&1,U32 & String,Dns.Reply>) -> Result<&1,&1,U32 & String,Routes>:
  match reply:
    case Done{Dns.Found{records}}:
      Done{routes(records)}
    case Done{Dns.DnsError{code}}:
      Fail{(code,"endpoint DNS lookup returned an error")}
    case Done{_}:
      Fail{(1,"endpoint DNS lookup did not return usable records")}
    case Fail{error}:
      Fail{error}

def lookup_routes(identity: Identity, resolver: DnsSource) -> IO(Result<&1,&1,U32 & String,Routes>):
  PeerKeys{_,key,_} = identity
  DnsResolver{origin,host,port,ms} = resolver
  do IO<Result<&1,&1,U32 & String,Routes>>:
    reply : Result<&1,&1,U32 & String,Dns.Reply> <- Dns.lookup(key,origin,host,port,ms)
    return dns_routes(reply)

def pkarr_routes(verified: Pkarr.Verification) -> Result<&1,&1,U32 & String,Routes>:
  match verified:
    case Pkarr.Verified{_,records}:
      Done{routes(records)}
    case _:
      Fail{(1,"invalid signed Pkarr endpoint packet")}

def verify_routes(identity: Identity, packet: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,Routes>):
  PeerKeys{_,key,_} = identity
  do IO<Result<&1,&1,U32 & String,Routes>>:
    verified : Pkarr.Verification <- Pkarr.verify(key,packet)
    return pkarr_routes(verified)

def connect_resolved(~C: Type, ~attempt: Dialer(C), planned: Result<&1,&1,U32 & String,Routes>,
    identity: Identity, timeouts: Timeouts) -> IO(TransportResult(C)):
  match planned:
    case Done{plan}:
      dial_plan(~C,~attempt,plan,identity,timeouts)
    case Fail{error}:
      IO.pure(TransportResult(C),Fail{error})

def from_dns(reply: Result<&1,&1,U32 & String,Dns.Reply>, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  connect_resolved(~Direct.QuicConnection,~direct_stream,dns_routes(reply),identity,timeouts)

def lookup_and_dial(+identity: Identity, resolver: DnsSource, timeouts: Timeouts) -> IO(Outcome()):
  do IO<Outcome()>:
    plan : Result<&1,&1,U32 & String,Routes> <- lookup_routes(identity,resolver)
    connect_resolved(~Direct.QuicConnection,~direct_stream,plan,identity,timeouts)

def from_pkarr(verified: Pkarr.Verification, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  connect_resolved(~Direct.QuicConnection,~direct_stream,pkarr_routes(verified),identity,timeouts)

def verify_and_dial(+identity: Identity, packet: List<&2,U32>, timeouts: Timeouts) -> IO(Outcome()):
  do IO<Outcome()>:
    plan : Result<&1,&1,U32 & String,Routes> <- verify_routes(identity,packet)
    connect_resolved(~Direct.QuicConnection,~direct_stream,plan,identity,timeouts)

def lookup_and_connect(+identity: Identity, resolver: DnsSource, timeouts: Timeouts) -> IO(ConnectResult()):
  do IO<ConnectResult()>:
    plan : Result<&1,&1,U32 & String,Routes> <- lookup_routes(identity,resolver)
    connect_resolved(~Quic.DatagramConnection,~direct_quic,plan,identity,timeouts)

def verify_and_connect(+identity: Identity, packet: List<&2,U32>, timeouts: Timeouts) -> IO(ConnectResult()):
  do IO<ConnectResult()>:
    plan : Result<&1,&1,U32 & String,Routes> <- verify_routes(identity,packet)
    connect_resolved(~Quic.DatagramConnection,~direct_quic,plan,identity,timeouts)

def keep_path(-R: Type, outcome: Quic.DatagramConnection & R, path: Maybe<&1,Path.Bridge>) -> Connection() & R:
  (conn,value) = outcome
  ((conn,path),value)

# Run a transport operation while retaining ownership of the selected path.
def use_connection(-R: Type, connected: Connection(), operation: Quic.DatagramConnection -> IO(Quic.DatagramConnection & R))
    -> IO(Connection() & R):
  (conn,path) = connected
  do IO<Connection() & R>:
    outcome : Quic.DatagramConnection & R <- operation(conn)
    return keep_path(R,outcome,path)

# Probe a new route while retaining ownership of the existing relay bridge, if present.
def start_path_migration(connected: Connection(), local: Address, remote: Address)
    -> IO(Connection() & Result<&1,&1,U32 & String,U32>):
  IpAddress{host,port} = local
  IpAddress{peer,peer_port} = remote
  use_connection(Result<&1,&1,U32 & String,U32>,connected,
    conn => Quic.start_quic_path_migration(conn,host,port,peer,peer_port))

def disconnect(connected: Connection()) -> IO(Result<&1,&1,U32 & String,Unit>):
  match connected:
    case (conn,None{}):
      do IO<Result<&1,&1,U32 & String,Unit>>:
        Quic.drop_quic_datagram(conn)
        return Done{Unit{}}
    case (conn,Some{path}):
      do IO<Result<&1,&1,U32 & String,Unit>>:
        Quic.drop_quic_datagram(conn)
        Path.stop(path)

type RecoveryPlan is Data:
  RelayFallback{identity: Identity, urls: List<&2,String>, probe_ms: U32}

type RecoveryState is Data:
  DirectOnly{}
  Watching{plan: RecoveryPlan}
  DialingRelay{plan: RecoveryPlan, remaining: List<&2,String>}
  ProbingRelay{plan: RecoveryPlan, remaining: List<&2,String>, port: U32, since: U32}
  ValidatingRelay{plan: RecoveryPlan, remaining: List<&2,String>}
  OnRelay{}

type RoutedConnection is Type:
  Routed{transport: Connection(), recovery: RecoveryState}

type SelectedRoute is Data:
  DirectRoute{}
  RelayRoute{}

def RoutedResult() -> Type:
  Result<&1,&1,U32 & String,RoutedConnection>

def RouteStep() -> Type:
  RoutedConnection & Result<&1,&1,U32 & String,SelectedRoute>

def route_step(conn: Connection(), state: RecoveryState, route: SelectedRoute) -> IO(RouteStep()):
  IO.pure(RouteStep(),(Routed{conn,state},Done{route}))

def route_error(conn: Connection(), state: RecoveryState, error: U32 & String) -> IO(RouteStep()):
  IO.pure(RouteStep(),(Routed{conn,state},Fail{error}))

def arm_recovery(conn: Connection()) -> IO(Connection() & Result<&1,&1,U32 & String,Unit>):
  use_connection(Result<&1,&1,U32 & String,Unit>,conn,c => Quic.monitor_quic_path(c,1000))

def start_watching(monitored: Connection() & Result<&1,&1,U32 & String,Unit>, plan: RecoveryPlan)
    -> IO(RoutedResult()):
  match monitored:
    case (conn,Done{_}):
      IO.pure(RoutedResult(),Done{Routed{conn,Watching{plan}}})
    case (conn,Fail{error}):
      do IO<RoutedResult()>:
        _ : Result<&1,&1,U32 & String,Unit> <- disconnect(conn)
        return Fail{error}

def routed_dial(result: ConnectResult(), urls: List<&2,String>, identity: Identity, timeouts: Timeouts)
    -> IO(RoutedResult()):
  match result urls:
    case Fail{error} _:
      IO.pure(RoutedResult(),Fail{error})
    case Done{(conn,Some{bridge})} _:
      IO.pure(RoutedResult(),Done{Routed{(conn,Some{bridge}),OnRelay{}}})
    case Done{(conn,None{})} Nil{}:
      IO.pure(RoutedResult(),Done{Routed{(conn,None{}),DirectOnly{}}})
    case Done{(conn,None{})} Con{url,rest}:
      HandshakeTimeouts{_,probe_ms} = timeouts
      do IO<RoutedResult()>:
        monitored : Connection() & Result<&1,&1,U32 & String,Unit> <- arm_recovery((conn,None{}))
        start_watching(monitored,RelayFallback{identity,Con{url,rest},probe_ms})

# Dial using the normal route order and retain relays for later recovery.
def connect_routed(+routes: Routes, +identity: Identity, +timeouts: Timeouts) -> IO(RoutedResult()):
  DialRoutes{_,urls} = routes
  do IO<RoutedResult()>:
    connected : ConnectResult() <- connect_routes(routes,identity,timeouts)
    routed_dial(connected,urls,identity,timeouts)

def restarted_monitor(monitored: Connection() & Result<&1,&1,U32 & String,Unit>, plan: RecoveryPlan) -> IO(RouteStep()):
  match monitored:
    case (conn,Done{_}):
      route_step(conn,Watching{plan},DirectRoute{})
    case (conn,Fail{error}):
      route_error(conn,Watching{plan},error)

def skip_relay(conn: Connection(), plan: RecoveryPlan, remaining: List<&2,String>) -> IO(RouteStep()):
  (quic,bridge) = conn
  match bridge:
    case None{}:
      route_step((quic,None{}),DialingRelay{plan,remaining},DirectRoute{})
    case Some{path}:
      do IO<RouteStep()>:
        _ : Result<&1,&1,U32 & String,Unit> <- Path.stop(path)
        route_step((quic,None{}),DialingRelay{plan,remaining},DirectRoute{})

def opened_relay(conn: Quic.DatagramConnection, attachment: Result<&1,&1,U32 & String,Path.Bridge & U32>,
    plan: RecoveryPlan, rest: List<&2,String>) -> IO(RouteStep()):
  match attachment:
    case Done{(bridge,port)}:
      do IO<RouteStep()>:
        now : U32 <- Quic.quic_millis()
        route_step((conn,Some{bridge}),ProbingRelay{plan,rest,port,now},DirectRoute{})
    case Fail{_}:
      route_step((conn,None{}),DialingRelay{plan,rest},DirectRoute{})

def start_standby(conn: Connection(), +plan: RecoveryPlan, url: String, rest: List<&2,String>) -> IO(RouteStep()):
  (quic,_) = conn
  RelayFallback{PeerKeys{seed,peer,_},_,_} = plan
  do IO<RouteStep()>:
    bridge : Result<&1,&1,U32 & String,Path.Bridge & U32> <- Path.start(url,seed,peer,0)
    opened_relay(quic,bridge,plan,rest)

def dial_standby(conn: Connection(), plan: RecoveryPlan, remaining: List<&2,String>) -> IO(RouteStep()):
  match remaining:
    case Con{url,rest}:
      start_standby(conn,plan,url,rest)
    case Nil{}:
      do IO<RouteStep()>:
        monitored : Connection() & Result<&1,&1,U32 & String,Unit> <- arm_recovery(conn)
        restarted_monitor(monitored,plan)

def watch_path(conn: Connection(), +plan: RecoveryPlan, stalled: Bool) -> IO(RouteStep()):
  RelayFallback{_,urls,_} = plan
  match stalled:
    case True{}:
      dial_standby(conn,plan,urls)
    case False{}:
      route_step(conn,Watching{plan},DirectRoute{})

def watch_input(input: Connection() & Result<&1,&1,U32 & String,U32 & U32>, plan: RecoveryPlan) -> IO(RouteStep()):
  match input:
    case (conn,Done{(+idle,pto)}):
      watch_path(conn,plan,U32.is_ge(idle,3500) && U32.is_ge(U32.div(idle,3),pto))
    case (conn,Fail{error}):
      route_error(conn,Watching{plan},error)

def after_relay_probe(result: Connection() & Result<&1,&1,U32 & String,U32>, plan: RecoveryPlan,
    remaining: List<&2,String>, port: U32, since: U32, expired: Bool) -> IO(RouteStep()):
  match result expired:
    case (conn,Done{0}) False{}:
      route_step(conn,ProbingRelay{plan,remaining,port,since},DirectRoute{})
    case (conn,Done{0}) True{}:
      skip_relay(conn,plan,remaining)
    case (conn,Done{_}) _:
      route_step(conn,ValidatingRelay{plan,remaining},DirectRoute{})
    case (conn,Fail{_}) _:
      skip_relay(conn,plan,remaining)

def completed_relay(result: Connection() & Result<&1,&1,U32 & String,Unit>) -> IO(RouteStep()):
  match result:
    case (conn,Done{_}):
      route_step(conn,OnRelay{},RelayRoute{})
    case (conn,Fail{error}):
      route_error(conn,OnRelay{},error)

def observe_relay(result: Connection() & Result<&1,&1,U32 & String,U32>, plan: RecoveryPlan,
    remaining: List<&2,String>) -> IO(RouteStep()):
  match result:
    case (conn,Done{2}):
      do IO<RouteStep()>:
        unmonitored : Connection() & Result<&1,&1,U32 & String,Unit> <-
          use_connection(Result<&1,&1,U32 & String,Unit>,conn,c => Quic.monitor_quic_path(c,0))
        completed_relay(unmonitored)
    case (conn,Done{1}):
      route_step(conn,ValidatingRelay{plan,remaining},DirectRoute{})
    case (conn,Done{_}):
      skip_relay(conn,plan,remaining)
    case (conn,Fail{error}):
      route_error(conn,ValidatingRelay{plan,remaining},error)

def advance_recovery(conn: Connection(), state: RecoveryState) -> IO(RouteStep()):
  match state:
    case DirectOnly{}:
      route_step(conn,DirectOnly{},DirectRoute{})
    case OnRelay{}:
      route_step(conn,OnRelay{},RelayRoute{})
    case Watching{plan}:
      do IO<RouteStep()>:
        timing : Connection() & Result<&1,&1,U32 & String,U32 & U32> <-
          use_connection(Result<&1,&1,U32 & String,U32 & U32>,conn,Quic.quic_path_timing)
        watch_input(timing,plan)
    case DialingRelay{plan,rest}:
      dial_standby(conn,plan,rest)
    case ProbingRelay{+plan,rest,+port,+since}:
      RelayFallback{_,_,timeout} = plan
      do IO<RouteStep()>:
        now : U32 <- Quic.quic_millis()
        candidate : Connection() & Result<&1,&1,U32 & String,U32> <-
          start_path_migration(conn,IpAddress{"127.0.0.1",0},IpAddress{"127.0.0.1",port})
        after_relay_probe(candidate,plan,rest,port,since,U32.is_ge(U32.sub(now,since),timeout))
    case ValidatingRelay{plan,rest}:
      do IO<RouteStep()>:
        validation : Connection() & Result<&1,&1,U32 & String,U32> <-
          use_connection(Result<&1,&1,U32 & String,U32>,conn,Quic.quic_migration_status)
        observe_relay(validation,plan,rest)

def recovery_progress(result: Connection() & Result<&1,&1,U32 & String,U32>, state: RecoveryState) -> IO(RouteStep()):
  match result:
    case (conn,Done{_}):
      advance_recovery(conn,state)
    case (conn,Fail{error}):
      route_error(conn,state,error)

# Drive QUIC and migrate the same connection to a relay after a direct outage.
def step_routes(owner: RoutedConnection) -> IO(RouteStep()):
  Routed{conn,state} = owner
  do IO<RouteStep()>:
    progress : Connection() & Result<&1,&1,U32 & String,U32> <-
      use_connection(Result<&1,&1,U32 & String,U32>,conn,Quic.step_quic_datagram)
    recovery_progress(progress,state)

def keep_routes(-R: Type, pair: Connection() & R, state: RecoveryState) -> RoutedConnection & R:
  (conn,value) = pair
  (Routed{conn,state},value)

def use_routed_connection(-R: Type, owner: RoutedConnection,
    operation: Quic.DatagramConnection -> IO(Quic.DatagramConnection & R)) -> IO(RoutedConnection & R):
  Routed{conn,state} = owner
  do IO<RoutedConnection & R>:
    result : Connection() & R <- use_connection(R,conn,operation)
    return keep_routes(R,result,state)

def close_routes(owner: RoutedConnection) -> IO(Result<&1,&1,U32 & String,Unit>):
  Routed{conn,_} = owner
  disconnect(conn)

def bind(address: Address, identity: Identity) -> IO(Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32>):
  IpAddress{host,port} = address
  PeerKeys{seed,peer,alpn} = identity
  Quic.bind_shared_quic(host,port,seed,peer,alpn)

def accepted(listener: Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.DatagramConnection>>)
    -> Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Connection()>>:
  match listener:
    case (owner,Done{Some{conn}}):
      (owner,Done{Some{(conn,None{})}})
    case (owner,Done{None{}}):
      (owner,Done{None{}})
    case (owner,Fail{error}):
      (owner,Fail{error})

def try_accept(listener: Quic.QuicDatagramListener)
    -> IO(Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Connection()>>):
  do IO<Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Connection()>>>:
    outcome : Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.DatagramConnection>> <-
      Quic.try_accept_shared_quic(listener)
    return accepted(outcome)

def close_listener(listener: Quic.QuicDatagramListener) -> IO(Unit):
  Quic.close_shared_quic(listener)

# Opt in to receiving replayable 0-RTT data on this listener.
def bind_resumable(address: Address, identity: Identity)
    -> IO(Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32>):
  IpAddress{host,port} = address
  PeerKeys{seed,peer,alpn} = identity
  Quic.bind_resumable_quic(host,port,seed,peer,alpn)
