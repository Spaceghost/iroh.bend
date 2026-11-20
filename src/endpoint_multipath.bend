import Base
import ./endpoint.bend as Endpoint
import ./endpoint_ticket.bend as Tickets
import ./quic_handshake_routes.bend as Race
import ./quic_multipath.bend as Quic
import ./quic_close.bend as Close
import ./quic_multipath_nat.bend as Nat
import ./quic_nat.bend as NatWire
import ./relay_quic.bend as Relay
import ./relay_quic_inbound.bend as Inbound

def Connection() -> Type:
  Endpoint.Transport(Quic.MultipathConnection)

def ConnectResult() -> Type:
  Endpoint.TransportResult(Quic.MultipathConnection)

type RelayedListener is Type:
  RelayListener{listener: Quic.MultipathListener, bridge: Relay.Bridge}

def attached_listener(bridge: Result<&1,&1,U32 & String,Relay.Bridge>, listener: Quic.MultipathListener, port: U32)
    -> IO(Result<&1,&1,U32 & String,RelayedListener & U32>):
  match bridge:
    case Done{path}:
      IO.pure(Result<&1,&1,U32 & String,RelayedListener & U32>,Done{(RelayListener{listener,path},port)})
    case Fail{error}:
      do IO<Result<&1,&1,U32 & String,RelayedListener & U32>>:
        Quic.close_multipath_listener(listener)
        return Fail{error}

def attach_inbound(bound: Result<&1,&1,U32 & String,Quic.MultipathListener & U32>, url: String, seed: List<&2,U32>,
    start: String -> List<&2,U32> -> U32 -> IO(Result<&1,&1,U32 & String,Relay.Bridge>))
    -> IO(Result<&1,&1,U32 & String,RelayedListener & U32>):
  match bound:
    case Done{(listener,+port)}:
      do IO<Result<&1,&1,U32 & String,RelayedListener & U32>>:
        bridge : Result<&1,&1,U32 & String,Relay.Bridge> <- start(url,seed,port)
        attached_listener(bridge,listener,port)
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,RelayedListener & U32>,Fail{error})

def attach_listener(bound: Result<&1,&1,U32 & String,Quic.MultipathListener & U32>, url: String, seed: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,RelayedListener & U32>):
  attach_inbound(bound,url,seed,address => secret => port => Inbound.start_background(address,secret,port))

def relay_only(bound: Result<&1,&1,U32 & String,RelayedListener & U32>) -> Result<&1,&1,U32 & String,RelayedListener>:
  match bound:
    case Done{(listener,_)}:
      Done{listener}
    case Fail{why}:
      Fail{why}

def bind_with_idle_timeout(address: Endpoint.Address, identity: Endpoint.Identity, idle_ms: NatWire.VarInt)
    -> IO(Result<&1,&1,U32 & String,Quic.MultipathListener & U32>):
  Endpoint.IpAddress{host,port} = address
  Endpoint.PeerKeys{seed,peer,alpn} = identity
  Quic.bind_multipath_bytes_with_idle_timeout(host,port,seed,peer,alpn,idle_ms)

# Register before returning the relay-only listener. The bridge owns the route
# from this relay to the local QUIC socket for all accepted peer connections.
def bind_relay_identity(url: String, +seed: List<&2,U32>, alpns: List<&2,List<&2,U32>>, early_data: U32)
    -> IO(Result<&1,&1,U32 & String,RelayedListener>):
  do IO<Result<&1,&1,U32 & String,RelayedListener>>:
    bound : Result<&1,&1,U32 & String,Quic.MultipathListener & U32> <-
      Quic.bind_multipath_identity("127.0.0.1",0,seed,alpns,early_data)
    attached : Result<&1,&1,U32 & String,RelayedListener & U32> <- attach_inbound(bound,url,seed,address => secret => port => Inbound.start(address,secret,port))
    return relay_only(attached)

# Both IP families and the relay feed a single Picoquic context. The
# listener owns relay registration for the lifetime of its connections.
def bind_direct_relay_identity(port: U32, url: String, +seed: List<&2,U32>, alpns: List<&2,List<&2,U32>>, early_data: U32)
    -> IO(Result<&1,&1,U32 & String,RelayedListener & U32>):
  do IO<Result<&1,&1,U32 & String,RelayedListener & U32>>:
    bound : Result<&1,&1,U32 & String,Quic.MultipathListener & U32> <-
      Quic.bind_dual_multipath_identity("::",port,seed,alpns,early_data)
    attach_listener(bound,url,seed)

def listener_result(result: Quic.MultipathListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>>,
    bridge: Relay.Bridge) -> RelayedListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>>:
  (listener,accepted) = result
  (RelayListener{listener,bridge},accepted)

def accept_listener(owner: RelayedListener)
    -> IO(RelayedListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>>):
  RelayListener{listener,bridge} = owner
  do IO<RelayedListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>>>:
    result : Quic.MultipathListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>> <-
      Quic.accept_multipath(listener)
    return listener_result(result,bridge)

def close_listener(owner: RelayedListener) -> IO(Result<&1,&1,U32 & String,Unit>):
  RelayListener{listener,bridge} = owner
  do IO<Result<&1,&1,U32 & String,Unit>>:
    Quic.close_multipath_listener(listener)
    Relay.stop(bridge)

def NatRelayedListener() -> Type:
  RelayedListener & U32

def BindNatRelayed() -> Type:
  Result<&1,&1,U32 & String,NatRelayedListener() & U32>

def AcceptNatRelayed() -> Type:
  NatRelayedListener() & Result<&1,&1,U32 & String,Maybe<&1,Nat.ListenerConnection()>>

def nat_listener_bound(bound: Result<&1,&1,U32 & String,RelayedListener & U32>, limit: U32) -> BindNatRelayed():
  match bound:
    case Done{(owner,port)}:
      Done{((owner,limit),port)}
    case Fail{error}:
      Fail{error}

def qad_name(parts: List<&2,String>) -> String:
  match parts:
    case Con{host,_}:
      host
    case Nil{}:
      ""

def qad_authority(+authority: String, bracketed: Bool, userinfo: Bool) -> String:
  match bracketed userinfo:
    case _ True{}:
      ""
    case True{} False{}:
      qad_name(String.split(String.drop(authority,1n),']'))
    case False{} False{}:
      qad_name(String.split(authority,':'))

def qad_path(parts: List<&2,String>) -> String:
  match parts:
    case Con{+authority,_}:
      qad_authority(qad_name(String.split(qad_name(String.split(authority,'?')),'#')),
        String.starts_with(authority,"["),String.contains(authority,"@"))
    case Nil{}:
      ""

def qad_host(+url: String, secure: Bool) -> String:
  match secure:
    case True{}:
      qad_path(String.split(String.drop(url,6n),'/'))
    case False{}:
      qad_path(String.split(String.drop(url,5n),'/'))

def observe_nat_listener(bound: Result<&1,&1,U32 & String,Quic.MultipathListener & U32>, +url: String)
    -> IO(Result<&1,&1,U32 & String,Quic.MultipathListener & U32>):
  match bound:
    case Done{(listener,port)}:
      do IO<Result<&1,&1,U32 & String,Quic.MultipathListener & U32>>:
        active : Quic.MultipathListener <-
          Quic.configure_listener_qad(listener,qad_host(url,String.starts_with(url,"wss://")),7842)
        return Done{(active,port)}
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Quic.MultipathListener & U32>,Fail{error})

def bind_nat_listener_offer(offer: Maybe<&2,List<&2,U32>>, port: U32, +url: String, +seed: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>, early_data: U32, limit: U32) -> IO(BindNatRelayed()):
  match offer:
    case Some{parameter}:
      do IO<BindNatRelayed()>:
        bound : Result<&1,&1,U32 & String,Quic.MultipathListener & U32> <-
          Quic.bind_dual_multipath_nat_identity("::",port,seed,alpns,early_data,parameter)
        observed : Result<&1,&1,U32 & String,Quic.MultipathListener & U32> <- observe_nat_listener(bound,url)
        attached : Result<&1,&1,U32 & String,RelayedListener & U32> <- attach_listener(observed,url,seed)
        return nat_listener_bound(attached,limit)
    case None{}:
      IO.pure(BindNatRelayed(),Fail{(22,"invalid NAT traversal limit")})

# Discover reachable addresses on the shared UDP sockets and allow explicit candidates per connection.
def bind_nat_listener(port: U32, url: String, seed: List<&2,U32>, alpns: List<&2,List<&2,U32>>,
    early_data: U32, +limit: U32) -> IO(BindNatRelayed()):
  bind_nat_listener_offer(NatWire.encode_limit(limit),port,url,seed,alpns,early_data,limit)

def accepted_nat(outcome: Nat.ListenerResult(), owner: NatRelayedListener()) -> AcceptNatRelayed():
  match outcome:
    case Done{connection}:
      (owner,Done{Some{connection}})
    case Fail{error}:
      (owner,Fail{error})

def initialize_accepted_nat(keepalive: Quic.MultipathConnection & Result<&1,&1,U32 & String,Unit>,
    owner: RelayedListener, +limit: U32) -> IO(AcceptNatRelayed()):
  match keepalive:
    case (connection,Done{_}):
      do IO<AcceptNatRelayed()>:
        initialized : Nat.ListenerResult() <- Nat.initialize_listener(connection,limit,True{})
        return accepted_nat(initialized,(owner,limit))
    case (connection,Fail{error}):
      do IO<AcceptNatRelayed()>:
        Quic.close_multipath(connection)
        return ((owner,limit),Fail{error})

def accept_nat_result(result: RelayedListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>>, +limit: U32)
    -> IO(AcceptNatRelayed()):
  match result:
    case (owner,Done{Some{connection}}):
      do IO<AcceptNatRelayed()>:
        # Continue testing the active path even while the application waits
        # for inbound data on an open stream.
        kept : Quic.MultipathConnection & Result<&1,&1,U32 & String,Unit> <-
          Quic.set_multipath_keepalive(connection,1000)
        initialize_accepted_nat(kept,owner,limit)
    case (owner,Done{None{}}):
      IO.pure(AcceptNatRelayed(),((owner,limit),Done{None{}}))
    case (owner,Fail{error}):
      IO.pure(AcceptNatRelayed(),((owner,limit),Fail{error}))

def accept_nat_listener(owner: NatRelayedListener()) -> IO(AcceptNatRelayed()):
  (listener,limit) = owner
  do IO<AcceptNatRelayed()>:
    result : RelayedListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>> <- accept_listener(listener)
    accept_nat_result(result,limit)

def close_nat_listener(owner: NatRelayedListener()) -> IO(Result<&1,&1,U32 & String,Unit>):
  (listener,_) = owner
  close_listener(listener)

def dial_address(address: Endpoint.Address, identity: Endpoint.Identity, timeout: U32) -> IO(Quic.ConnectResult()):
  Endpoint.IpAddress{host,port} = address
  Endpoint.PeerKeys{seed,peer,alpn} = identity
  Quic.connect_multipath_bytes(host,port,seed,peer,alpn,U32.to_nat(timeout))

def dial(address: Endpoint.Address, +identity: Endpoint.Identity, timeout: U32) -> IO(Quic.ConnectResult()):
  Endpoint.before_connect(Quic.MultipathConnection,identity,u => dial_address(address,identity,timeout))

# Use the automatic NAT traversal driver for a direct bootstrap address.
def connect_nat_direct(address: Endpoint.Address, +identity: Endpoint.Identity, timeout: U32, limit: U32)
    -> IO(Nat.ConnectResult()):
  Endpoint.IpAddress{host,port} = address
  Endpoint.PeerKeys{seed,peer,alpn} = identity
  Endpoint.before_connect(Nat.Connection(),identity,u => Nat.connect(host,port,seed,peer,alpn,limit,U32.to_nat(timeout)))

def step_nat_direct(connection: Nat.Connection()) -> IO(Nat.Connection() & Nat.NewPathResult()):
  Nat.step(connection)

def NatRelayConnection() -> Type:
  Endpoint.Transport(Nat.Connection())

def NatRelayResult() -> Type:
  Endpoint.TransportResult(Nat.Connection())

def observe_nat_relay(outcome: Nat.ConnectResult(), relay: Relay.Bridge, discovery: Maybe<&2,Nat.DiscoveryOptions>)
    -> IO(NatRelayResult()):
  match outcome discovery:
    case Done{(conn,state)} Some{server}:
      do IO<NatRelayResult()>:
        observed : Nat.ConnectResult() <- Nat.discover_address(conn,state,server)
        Endpoint.attach_connection(Nat.Connection(),observed,relay)
    case result _:
      Endpoint.attach_connection(Nat.Connection(),result,relay)

def attach_nat_relay(result: Result<&1,&1,U32 & String,Relay.Bridge & U32>, identity: Endpoint.Identity,
    source: Endpoint.Address, limit: U32, timeout: U32, discovery: Maybe<&2,Nat.DiscoveryOptions>) -> IO(NatRelayResult()):
  match result:
    case Done{(bridge,port)}:
      Endpoint.PeerKeys{seed,peer,alpn} = identity
      Endpoint.IpAddress{local_ip,local_port} = source
      do IO<NatRelayResult()>:
        connected : Nat.ConnectResult() <-
          Nat.connect_from("127.0.0.1",port,seed,peer,alpn,local_ip,local_port,limit,U32.to_nat(timeout))
        observe_nat_relay(connected,bridge,discovery)
    case Fail{error}:
      IO.pure(NatRelayResult(),Fail{error})

def connect_nat_relay_using(url: String, +identity: Endpoint.Identity, source: Endpoint.Address,
    timeout: U32, limit: U32, discovery: Maybe<&2,Nat.DiscoveryOptions>) -> IO(NatRelayResult()):
  Endpoint.PeerKeys{seed,peer,_} = identity
  Endpoint.before_connect(NatRelayConnection(),identity,u =>
    do IO<NatRelayResult()>:
      result : Result<&1,&1,U32 & String,Relay.Bridge & U32> <- Relay.start(url,seed,peer,0)
      attach_nat_relay(result,identity,source,limit,timeout,discovery))

# Bootstrap through an authenticated relay and probe with a reachable UDP source.
def connect_nat_relay(url: String, identity: Endpoint.Identity, source: Endpoint.Address,
    timeout: U32, limit: U32) -> IO(NatRelayResult()):
  connect_nat_relay_using(url,identity,source,timeout,limit,None{})

# Discover the public mapping of the probe socket via a configured QUIC service.
def connect_nat_relay_observed(url: String, identity: Endpoint.Identity, source: Endpoint.Address,
    timeout: U32, limit: U32, discovery: Nat.DiscoveryOptions) -> IO(NatRelayResult()):
  connect_nat_relay_using(url,identity,source,timeout,limit,Some{discovery})

def keep_nat_relay(result: Nat.Connection() & Nat.NewPathResult(), relay: Maybe<&1,Relay.Bridge>)
    -> NatRelayConnection() & Nat.NewPathResult():
  (connection,path) = result
  ((connection,relay),path)

def step_nat_relay(owner: NatRelayConnection()) -> IO(NatRelayConnection() & Nat.NewPathResult()):
  (connection,relay) = owner
  do IO<NatRelayConnection() & Nat.NewPathResult()>:
    result : Nat.Connection() & Nat.NewPathResult() <- Nat.step(connection)
    return keep_nat_relay(result,relay)

def shared_handshake() -> Race.Backend<Quic.MultipathConnection>:
  Race.Backend{Quic.start_multipath_route_handshake,Quic.open_multipath_handshake_socket,
    Quic.read_multipath_handshake_socket,Quic.multipath_handshake_output,Quic.adopt_multipath_handshake_socket,
    Quic.close_multipath,"QUIC multipath handshake timed out"}

def connect_with_lookup_and_idle_timeout(plan: Endpoint.Routes, +identity: Endpoint.Identity, timeouts: Endpoint.Timeouts,
    sources: List<&2,Endpoint.AddressLookup>, idle_ms: NatWire.VarInt) -> IO(ConnectResult()):
  Endpoint.before_connect(Connection(),identity,u => Endpoint.start_dial_using(~Quic.MultipathConnection,~shared_handshake(),
    ~Quic.start_multipath_route_handshake_with_idle_timeout,idle_ms,plan,identity,timeouts,sources))

def connect_routes_with_idle_timeout(plan: Endpoint.Routes, identity: Endpoint.Identity, timeouts: Endpoint.Timeouts,
    idle_ms: NatWire.VarInt) -> IO(ConnectResult()):
  connect_with_lookup_and_idle_timeout(plan,identity,timeouts,[],idle_ms)

def connect_with_lookup(plan: Endpoint.Routes, +identity: Endpoint.Identity, timeouts: Endpoint.Timeouts,
    sources: List<&2,Endpoint.AddressLookup>) -> IO(ConnectResult()):
  connect_with_lookup_and_idle_timeout(plan,identity,timeouts,sources,Close.default_idle_timeout())

def connect_routes(routes: Endpoint.Routes, identity: Endpoint.Identity, timeouts: Endpoint.Timeouts)
    -> IO(ConnectResult()):
  connect_with_lookup(routes,identity,timeouts,[])

def connect_ticket(text: String, seed: List<&2,U32>, alpn: List<&2,U32>, timeouts: Endpoint.Timeouts) -> IO(ConnectResult()):
  Endpoint.with_ticket(~Connection(),~connect_routes,text,seed,alpn,timeouts)

def connect_ticket_with_lookup(text: String, seed: List<&2,U32>, alpn: List<&2,U32>, timeouts: Endpoint.Timeouts,
    sources: List<&2,Endpoint.AddressLookup>) -> IO(ConnectResult()):
  do IO<ConnectResult()>:
    ticket : Maybe<&2,Tickets.EndpointTicket> <- Tickets.decode(text)
    Endpoint.ticket_action(Connection(),ticket,seed,alpn,plan => identity => connect_with_lookup(plan,identity,timeouts,sources))

def lookup_and_connect(identity: Endpoint.Identity, resolver: Endpoint.DnsSource, timeouts: Endpoint.Timeouts)
    -> IO(ConnectResult()):
  connect_with_lookup(Endpoint.DialRoutes{[],[]},identity,timeouts,[Endpoint.DnsLookup{resolver}])

def dial_verified(result: Result<&1,&1,U32 & String,Endpoint.Routes>, identity: Endpoint.Identity,
    timeouts: Endpoint.Timeouts) -> IO(ConnectResult()):
  match result:
    case Done{plan}:
      Endpoint.start_dial_using(~Quic.MultipathConnection,~shared_handshake(),~Quic.start_multipath_route_handshake_with_idle_timeout,
        Close.default_idle_timeout(),plan,identity,timeouts,[])
    case Fail{error}:
      IO.pure(ConnectResult(),Fail{error})

def verify_and_connect(+identity: Endpoint.Identity, packet: List<&2,U32>, timeouts: Endpoint.Timeouts)
    -> IO(ConnectResult()):
  Endpoint.before_connect(Connection(),identity,u =>
    do IO<ConnectResult()>:
      result : Result<&1,&1,U32 & String,Endpoint.Routes> <- Endpoint.verify_routes(identity,packet)
      dial_verified(result,identity,timeouts))

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

def close_with(connection: Connection(), code: NatWire.VarInt, reason: List<&2,U32>)
    -> IO(Connection() & Close.WriteResult()):
  use_connection(Close.WriteResult(),connection,c => Quic.close_multipath_connection(c,code,reason))

def close_reason(connection: Connection()) -> IO(Connection() & Close.ReadResult()):
  use_connection(Close.ReadResult(),connection,Quic.multipath_close_reason)

def disconnect(connection: Connection()) -> IO(Result<&1,&1,U32 & String,Unit>):
  (conn,bridge) = connection
  do IO<Result<&1,&1,U32 & String,Unit>>:
    Quic.close_multipath(conn)
    stop_bridge(bridge)

def disconnect_nat_relay(owner: NatRelayConnection()) -> IO(Result<&1,&1,U32 & String,Unit>):
  ((conn,_),relay) = owner
  disconnect((conn,relay))

type BackupPlan is Data:
  BackupRoutes{identity: Endpoint.Identity, urls: List<&2,String>, timeout: U32}

type BackupState is Data:
  DialBackup{remaining: List<&2,String>, since: U32}
  ProbeBackup{remaining: List<&2,String>, port: U32, since: U32}
  ValidateBackup{remaining: List<&2,String>, path: U32, since: U32}
  StandbyBackup{path: U32}
  ActiveBackup{path: U32}

type ProbeState is Data:
  Disabled{}
  Seeking{remaining: List<&2,Endpoint.Address>, since: U32}
  Validating{remaining: List<&2,Endpoint.Address>, path: U32, since: U32}
  DirectPath{path: U32}
  Waiting{since: U32}
  Backup{plan: BackupPlan, phase: BackupState}
  Rechecking{relay: U32, direct: ProbeState}
  RelayNat{direct: ProbeState, driver: Nat.Dialer}

type RoutedConnection is Type:
  Routed{transport: Connection(), candidates: List<&2,Endpoint.Address>, state: ProbeState}

type SelectedPath is Data:
  InitialPath{}
  PromotedPath{id: U32}
  RecoveredRelay{id: U32}

def RoutedResult() -> Type:
  Result<&1,&1,U32 & String,RoutedConnection>

def PathResult() -> Type:
  Result<&1,&1,U32 & String,SelectedPath>

def route_state(base: Connection(), +candidates: List<&2,Endpoint.Address>, urls: List<&2,String>,
    identity: Endpoint.Identity, timeouts: Endpoint.Timeouts, +now: U32) -> RoutedConnection:
  match base urls:
    case (conn,Some{bridge}) _:
      Routed{(conn,Some{bridge}),candidates,Seeking{candidates,now}}
    case (conn,None{}) Nil{}:
      Routed{(conn,None{}),[],Disabled{}}
    case (conn,None{}) Con{+url,+rest}:
      Endpoint.HandshakeTimeouts{_,timeout} = timeouts
      Routed{(conn,None{}),candidates,Backup{BackupRoutes{identity,Con{url,rest},timeout},DialBackup{Con{url,rest},now}}}

def routed_nat_limit() -> U32:
  64

def dial_relay_offer(address: Endpoint.Address, identity: Endpoint.Identity, timeout: U32) -> IO(Quic.ConnectResult()):
  Endpoint.IpAddress{host,port} = address
  Endpoint.PeerKeys{seed,peer,alpn} = identity
  Quic.connect_multipath_bytes_with_nat_limit(host,port,seed,peer,alpn,routed_nat_limit(),U32.to_nat(timeout))

def start_routed_offer(encoded: Maybe<&2,Race.Packet()>, host: String, port: U32, seed: Race.Packet(), peer: Race.Packet(),
    alpn: Race.Packet()) -> Race.Started(Quic.MultipathConnection):
  match encoded:
    case Some{parameter}:
      Quic.start_multipath_nat_route_handshake(host,port,seed,peer,alpn,parameter)
    case None{}:
      IO.pure(Result<&1,&1,U32 & String,Quic.MultipathConnection & Socket>,Fail{(22,"invalid NAT traversal limit")})

def start_routed_handshake(host: String, port: U32, seed: Race.Packet(), peer: Race.Packet(), alpn: Race.Packet())
    -> Race.Started(Quic.MultipathConnection):
  start_routed_offer(NatWire.encode_limit(routed_nat_limit()),host,port,seed,peer,alpn)

def routed_handshake() -> Race.Backend<Quic.MultipathConnection>:
  Race.Backend{start_routed_handshake,Quic.open_multipath_handshake_socket,
    Quic.read_multipath_handshake_socket,Quic.multipath_handshake_output,Quic.adopt_multipath_handshake_socket,
    Quic.close_multipath,"QUIC multipath handshake timed out"}

def configure_relay_qad(conn: Quic.MultipathConnection, +url: String) -> IO(Quic.MultipathConnection):
  # Iroh publishes QAD on its default QUIC port, independent of the WS port.
  Quic.configure_routed_qad(conn,qad_host(url,String.starts_with(url,"wss://")),7842)

def relay_route_ready(pair: Quic.MultipathConnection & Nat.DialerResult(), bridge: Relay.Bridge,
    +candidates: List<&2,Endpoint.Address>, now: U32) -> RoutedResult():
  match pair:
    case (conn,Done{driver}):
      Done{Routed{(conn,Some{bridge}),candidates,RelayNat{Seeking{candidates,now},driver}}}
    case (conn,Fail{_}):
      Done{Routed{(conn,Some{bridge}),candidates,Seeking{candidates,now}}}

def setup_routed(result: ConnectResult(), candidates: List<&2,Endpoint.Address>, urls: List<&2,String>,
    identity: Endpoint.Identity, timeouts: Endpoint.Timeouts, now: U32) -> IO(RoutedResult()):
  match result:
    case Done{(conn,Some{+bridge})}:
      do IO<RoutedResult()>:
        configured : Quic.MultipathConnection <- configure_relay_qad(conn,Relay.bridge_url(bridge))
        driver : Quic.MultipathConnection & Nat.DialerResult() <- Nat.initialize_relay(configured,routed_nat_limit())
        return relay_route_ready(driver,bridge,candidates,now)
    case Done{owner}:
      IO.pure(RoutedResult(),Done{route_state(owner,candidates,urls,identity,timeouts,now)})
    case Fail{error}:
      IO.pure(RoutedResult(),Fail{error})

def connect_routed(+routes: Endpoint.Routes, +identity: Endpoint.Identity, +timeouts: Endpoint.Timeouts)
    -> IO(RoutedResult()):
  Endpoint.DialRoutes{candidates,urls} = routes
  do IO<RoutedResult()>:
    result : ConnectResult() <- Endpoint.before_connect(Connection(),identity,u =>
      Endpoint.start_dial_with(~Quic.MultipathConnection,~routed_handshake(),routes,identity,timeouts,[]))
    now : U32 <- Quic.multipath_millis()
    setup_routed(result,candidates,urls,identity,timeouts,now)

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

def standby(conn: Connection(), path: U32, value: U32) -> IO(Connection() & Result<&1,&1,U32 & String,Unit>):
  use_connection(Result<&1,&1,U32 & String,Unit>,conn,c => Quic.set_multipath_standby(c,path,value))

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
    +path: U32, relay_path: U32, since: U32, now: U32, expired: Bool) -> IO(Connection() & ProbeState):
  match outcome expired:
    case (conn,Done{1}) _:
      do IO<Connection() & ProbeState>:
        preferred : Connection() & Result<&1,&1,U32 & String,Unit> <- standby(conn,relay_path,1)
        return promote(preferred,path,rest,now)
    case (conn,Done{0}) False{}:
      IO.pure(Connection() & ProbeState,(conn,Validating{rest,path,since}))
    case (conn,Done{0}) True{}:
      alternate(conn,rest,path,now)
    case (conn,_) _:
      do IO<Connection() & ProbeState>:
        kept : Connection() <- retire(conn,path)
        return (kept,Seeking{rest,now})

def demote_direct(outcome: Connection() & Result<&1,&1,U32 & String,Unit>, path: U32, now: U32)
    -> IO(Connection() & ProbeState):
  match outcome:
    case (conn,Done{_}):
      do IO<Connection() & ProbeState>:
        kept : Connection() <- retire(conn,path)
        return (kept,Waiting{now})
    case (conn,Fail{_}):
      IO.pure(Connection() & ProbeState,(conn,DirectPath{path}))

def failover(outcome: Connection() & Result<&1,&1,U32 & String,U32>, path: U32, relay_path: U32, now: U32)
    -> IO(Connection() & ProbeState):
  match outcome:
    case (conn,Done{1}):
      do IO<Connection() & ProbeState>:
        relay : Connection() & Result<&1,&1,U32 & String,Unit> <- standby(conn,relay_path,0)
        demote_direct(relay,path,now)
    case (conn,_):
      IO.pure(Connection() & ProbeState,(conn,DirectPath{path}))

def keep_direct(conn: Connection(), path: U32, +relay_path: U32, now: U32, healthy: Bool)
    -> IO(Connection() & ProbeState):
  match healthy:
    case True{}:
      IO.pure(Connection() & ProbeState,(conn,DirectPath{path}))
    case False{}:
      do IO<Connection() & ProbeState>:
        available : Connection() & Result<&1,&1,U32 & String,U32> <- check_path(conn,relay_path)
        failover(available,path,relay_path,now)

def path_timeouts(conn: Connection(), path: U32) -> IO(Connection() & Result<&1,&1,U32 & String,U32>):
  use_connection(Result<&1,&1,U32 & String,U32>,conn,c => Quic.multipath_path_timeouts(c,path))

def direct_health(outcome: Connection() & Result<&1,&1,U32 & String,U32>, path: U32, relay_path: U32,
    now: U32) -> IO(Connection() & ProbeState):
  match outcome:
    case (conn,Done{count}):
      keep_direct(conn,path,relay_path,now,U32.is_lt(count,2))
    case (conn,Fail{_}):
      keep_direct(conn,path,relay_path,now,False{})

def watch_direct(outcome: Connection() & Result<&1,&1,U32 & String,U32>, +path: U32, relay_path: U32,
    now: U32) -> IO(Connection() & ProbeState):
  match outcome:
    case (conn,Done{1}):
      do IO<Connection() & ProbeState>:
        timeouts : Connection() & Result<&1,&1,U32 & String,U32> <- path_timeouts(conn,path)
        direct_health(timeouts,path,relay_path,now)
    case (conn,_):
      keep_direct(conn,path,relay_path,now,False{})

def retry_routes(conn: Connection(), candidates: List<&2,Endpoint.Address>, since: U32,
    +now: U32, elapsed: Bool) -> IO(Connection() & ProbeState):
  match elapsed:
    case True{}:
      seek(conn,candidates,now,now)
    case False{}:
      IO.pure(Connection() & ProbeState,(conn,Waiting{since}))

def BackupProgress() -> Type:
  Connection() & BackupState

def backup_progress(conn: Connection(), state: BackupState) -> IO(BackupProgress()):
  IO.pure(BackupProgress(),(conn,state))

def stop_backup(conn: Connection(), rest: List<&2,String>, now: U32) -> IO(BackupProgress()):
  (quic,bridge) = conn
  do IO<BackupProgress()>:
    _ : Result<&1,&1,U32 & String,Unit> <- stop_bridge(bridge)
    return ((quic,None{}),DialBackup{rest,now})

def attached_backup(result: Result<&1,&1,U32 & String,Relay.Bridge & U32>, quic: Quic.MultipathConnection,
    rest: List<&2,String>, now: U32) -> BackupProgress():
  match result:
    case Done{(bridge,port)}:
      ((quic,Some{bridge}),ProbeBackup{rest,port,now})
    case Fail{_}:
      ((quic,None{}),DialBackup{rest,now})

def open_backup(conn: Connection(), identity: Endpoint.Identity, url: String, rest: List<&2,String>,
    now: U32) -> IO(BackupProgress()):
  (quic,_) = conn
  Endpoint.PeerKeys{seed,peer,_} = identity
  do IO<BackupProgress()>:
    result : Result<&1,&1,U32 & String,Relay.Bridge & U32> <- Relay.start(url,seed,peer,0)
    return attached_backup(result,quic,rest,now)

def dial_backup(conn: Connection(), identity: Endpoint.Identity, urls: List<&2,String>,
    remaining: List<&2,String>, since: U32, now: U32, retry: Bool) -> IO(BackupProgress()):
  match remaining retry:
    case Nil{} False{}:
      backup_progress(conn,DialBackup{[],since})
    case Nil{} True{}:
      backup_progress(conn,DialBackup{urls,now})
    case Con{url,rest} _:
      open_backup(conn,identity,url,rest,now)

def finish_backup_probe(outcome: Connection() & Result<&1,&1,U32 & String,Maybe<&1,U32>>,
    rest: List<&2,String>, port: U32, since: U32, now: U32, expired: Bool) -> IO(BackupProgress()):
  match outcome expired:
    case (conn,Done{Some{path}}) _:
      backup_progress(conn,ValidateBackup{rest,path,since})
    case (conn,Done{None{}}) False{}:
      backup_progress(conn,ProbeBackup{rest,port,since})
    case (conn,_) _:
      stop_backup(conn,rest,now)

def arm_backup(outcome: Connection() & Result<&1,&1,U32 & String,Unit>, path: U32,
    rest: List<&2,String>, now: U32) -> IO(BackupProgress()):
  match outcome:
    case (conn,Done{_}):
      do IO<BackupProgress()>:
        watched : Connection() & Result<&1,&1,U32 & String,Unit> <-
          use_connection(Result<&1,&1,U32 & String,Unit>,conn,c => Quic.set_multipath_keepalive(c,1000))
        return (without_status(watched),StandbyBackup{path})
    case (conn,Fail{_}):
      do IO<BackupProgress()>:
        kept : Connection() <- retire(conn,path)
        stop_backup(kept,rest,now)

def finish_backup_validation(outcome: Connection() & Result<&1,&1,U32 & String,U32>,
    rest: List<&2,String>, +path: U32, since: U32, now: U32, expired: Bool) -> IO(BackupProgress()):
  match outcome expired:
    case (conn,Done{1}) _:
      do IO<BackupProgress()>:
        marked : Connection() & Result<&1,&1,U32 & String,Unit> <- standby(conn,path,1)
        arm_backup(marked,path,rest,now)
    case (conn,Done{0}) False{}:
      backup_progress(conn,ValidateBackup{rest,path,since})
    case (conn,_) _:
      do IO<BackupProgress()>:
        kept : Connection() <- retire(conn,path)
        stop_backup(kept,rest,now)

def activate_backup(outcome: Connection() & Result<&1,&1,U32 & String,Unit>, path: U32) -> IO(BackupProgress()):
  match outcome:
    case (conn,Done{_}):
      do IO<BackupProgress()>:
        relayed : Connection() <- retire(conn,0)
        return (relayed,ActiveBackup{path})
    case (conn,Fail{_}):
      backup_progress(conn,StandbyBackup{path})

def use_backup(conn: Connection(), +path: U32, failed: Bool) -> IO(BackupProgress()):
  match failed:
    case False{}:
      backup_progress(conn,StandbyBackup{path})
    case True{}:
      do IO<BackupProgress()>:
        active : Connection() & Result<&1,&1,U32 & String,Unit> <- standby(conn,path,0)
        activate_backup(active,path)

def check_direct_progress(progress: Connection() & Result<&1,&1,U32 & String,U32>, path: U32)
    -> IO(BackupProgress()):
  match progress:
    case (conn,Done{count}):
      use_backup(conn,path,U32.is_ge(count,2))
    case (conn,Fail{_}):
      use_backup(conn,path,True{})

def watch_backup(progress: Connection() & Result<&1,&1,U32 & String,U32>, +path: U32,
    urls: List<&2,String>, now: U32) -> IO(BackupProgress()):
  match progress:
    case (conn,Done{1}):
      do IO<BackupProgress()>:
        timeouts : Connection() & Result<&1,&1,U32 & String,U32> <- path_timeouts(conn,0)
        check_direct_progress(timeouts,path)
    case (conn,_):
      do IO<BackupProgress()>:
        kept : Connection() <- retire(conn,path)
        stop_backup(kept,urls,now)

def advance_backup(conn: Connection(), plan: BackupPlan, phase: BackupState, +now: U32) -> IO(BackupProgress()):
  BackupRoutes{identity,urls,timeout} = plan
  match phase:
    case DialBackup{rest,+since}:
      dial_backup(conn,identity,urls,rest,since,now,U32.is_ge(U32.sub(now,since),1000))
    case ProbeBackup{rest,+port,+since}:
      do IO<BackupProgress()>:
        probe : Connection() & Result<&1,&1,U32 & String,Maybe<&1,U32>> <-
          probe_direct(conn,Endpoint.IpAddress{"127.0.0.1",0},Endpoint.IpAddress{"127.0.0.1",port})
        finish_backup_probe(probe,rest,port,since,now,U32.is_ge(U32.sub(now,since),timeout))
    case ValidateBackup{rest,+path,+since}:
      do IO<BackupProgress()>:
        status : Connection() & Result<&1,&1,U32 & String,U32> <- check_path(conn,path)
        finish_backup_validation(status,rest,path,since,now,U32.is_ge(U32.sub(now,since),timeout))
    case StandbyBackup{+path}:
      do IO<BackupProgress()>:
        status : Connection() & Result<&1,&1,U32 & String,U32> <- check_path(conn,path)
        watch_backup(status,path,urls,now)
    case ActiveBackup{path}:
      backup_progress(conn,ActiveBackup{path})

def keep_backup(progress: BackupProgress(), plan: BackupPlan, now: U32) -> Connection() & ProbeState:
  match progress:
    case (conn,ActiveBackup{path}):
      (conn,Rechecking{path,Waiting{now}})
    case (conn,next):
      (conn,Backup{plan,next})

def advance_direct(conn: Connection(), candidates: List<&2,Endpoint.Address>, state: ProbeState,
    relay_path: U32, +now: U32) -> IO(Connection() & ProbeState):
  match state:
    case Seeking{rest,since}:
      seek(conn,rest,since,now)
    case Validating{+rest,+path,+since}:
      do IO<Connection() & ProbeState>:
        status : Connection() & Result<&1,&1,U32 & String,U32> <- check_path(conn,path)
        finish_check(status,rest,path,relay_path,since,now,U32.is_ge(U32.sub(now,since),validation_wait(rest)))
    case DirectPath{+path}:
      do IO<Connection() & ProbeState>:
        status : Connection() & Result<&1,&1,U32 & String,U32> <- check_path(conn,path)
        watch_direct(status,path,relay_path,now)
    case Waiting{+since}:
      retry_routes(conn,candidates,since,now,U32.is_ge(U32.sub(now,since),1000))
    case inactive:
      IO.pure(Connection() & ProbeState,(conn,inactive))

def keep_rechecking(progress: Connection() & ProbeState, relay_path: U32) -> Connection() & ProbeState:
  (conn,next) = progress
  (conn,Rechecking{relay_path,next})

def keep_relay_nat(progress: Connection() & ProbeState, driver: Nat.Dialer) -> Connection() & ProbeState:
  (conn,current) = progress
  (conn,RelayNat{current,driver})

def keep_published(conn: Connection(), candidates: List<&2,Endpoint.Address>, phase: ProbeState,
    driver: Nat.Dialer, now: U32) -> IO(Connection() & ProbeState):
  do IO<Connection() & ProbeState>:
    progress : Connection() & ProbeState <- advance_direct(conn,candidates,phase,0,now)
    return keep_relay_nat(progress,driver)

def choose_punched(conn: Connection(), candidates: List<&2,Endpoint.Address>, phase: ProbeState,
    driver: Nat.Dialer, now: U32, path: Maybe<&1,U32>) -> IO(Connection() & ProbeState):
  match path:
    case Some{+id}:
      do IO<Connection() & ProbeState>:
        preferred : Connection() & Result<&1,&1,U32 & String,Unit> <- standby(conn,0,1)
        return keep_relay_nat(promote(preferred,id,[],now),driver)
    case None{}:
      keep_published(conn,candidates,phase,driver,now)

def punched(result: Quic.MultipathConnection & Nat.DialerResult(), bridge: Maybe<&1,Relay.Bridge>,
    candidates: List<&2,Endpoint.Address>, phase: ProbeState, now: U32) -> IO(Connection() & ProbeState):
  match result:
    case (conn,Done{+driver}):
      choose_punched((conn,bridge),candidates,phase,driver,now,Nat.direct_path(driver))
    case (conn,Fail{_}):
      advance_direct((conn,bridge),candidates,phase,0,now)

def relayed_traversal(owner: Connection(), candidates: List<&2,Endpoint.Address>, phase: ProbeState,
    driver: Nat.Dialer, now: U32) -> IO(Connection() & ProbeState):
  (conn,bridge) = owner
  do IO<Connection() & ProbeState>:
    progress : Quic.MultipathConnection & Nat.DialerResult() <- Nat.drive_ready((conn,Done{2}),Nat.retry_path(driver))
    punched(progress,bridge,candidates,phase,now)

def keep_maintained(result: Quic.MultipathConnection & Nat.DialerResult(), bridge: Maybe<&1,Relay.Bridge>,
    candidates: List<&2,Endpoint.Address>, phase: ProbeState, now: U32) -> IO(Connection() & ProbeState):
  match result:
    case (conn,Done{driver}):
      keep_published((conn,bridge),candidates,phase,driver,now)
    case (conn,Fail{_}):
      advance_direct((conn,bridge),candidates,phase,0,now)

def maintain_relay_nat(owner: Connection(), candidates: List<&2,Endpoint.Address>, +path: U32,
    driver: Nat.Dialer, now: U32) -> IO(Connection() & ProbeState):
  (conn,bridge) = owner
  do IO<Connection() & ProbeState>:
    result : Quic.MultipathConnection & Nat.DialerResult() <- Nat.drive_ready((conn,Done{2}),Nat.hold_path(driver,path))
    keep_maintained(result,bridge,candidates,DirectPath{path},now)

def advance_relay_nat(conn: Connection(), candidates: List<&2,Endpoint.Address>, phase: ProbeState,
    driver: Nat.Dialer, now: U32) -> IO(Connection() & ProbeState):
  match phase:
    case Waiting{since}:
      relayed_traversal(conn,candidates,Waiting{since},driver,now)
    case DirectPath{path}:
      maintain_relay_nat(conn,candidates,path,driver,now)
    case current:
      keep_published(conn,candidates,current,driver,now)

def advance(conn: Connection(), candidates: List<&2,Endpoint.Address>, state: ProbeState, +now: U32)
    -> IO(Connection() & ProbeState):
  match state:
    case RelayNat{phase,driver}:
      advance_relay_nat(conn,candidates,phase,driver,now)
    case Backup{+plan,phase}:
      do IO<Connection() & ProbeState>:
        progress : BackupProgress() <- advance_backup(conn,plan,phase,now)
        return keep_backup(progress,plan,now)
    case Rechecking{+relay_path,direct}:
      do IO<Connection() & ProbeState>:
        progress : Connection() & ProbeState <- advance_direct(conn,candidates,direct,relay_path,now)
        return keep_rechecking(progress,relay_path)
    case initial:
      advance_direct(conn,candidates,initial,0,now)

def selected(state: ProbeState) -> SelectedPath:
  match state:
    case RelayNat{current,_}:
      selected(current)
    case DirectPath{id}:
      PromotedPath{id}
    case Rechecking{_,DirectPath{id}}:
      PromotedPath{id}
    case Rechecking{id,_}:
      RecoveredRelay{id}
    case Backup{_,ActiveBackup{id}}:
      RecoveredRelay{id}
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

# Drive QUIC and maintain direct and standby relay paths.
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
