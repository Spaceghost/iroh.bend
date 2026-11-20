import Base
import ./endpoint.bend as Endpoint
import ./quic_multipath.bend as Quic
import ./relay_quic.bend as Relay

def Connection() -> Type:
  Endpoint.Transport(Quic.MultipathConnection)

def ConnectResult() -> Type:
  Endpoint.TransportResult(Quic.MultipathConnection)

def text_alpn(bytes: List<&2,U32>) -> Bool:
  match bytes:
    case Nil{}:
      True{}
    case Con{+byte,rest}:
      U32.is_ge(byte,1) && U32.is_le(byte,127) && text_alpn(rest)

def dial_text(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, timeout: U32, valid: Bool) -> IO(Quic.ConnectResult()):
  match valid:
    case True{}:
      Quic.connect_multipath(host,port,seed,peer,String.from_list(Endpoint.as_chars(alpn)),U32.to_nat(timeout))
    case False{}:
      IO.pure(Quic.ConnectResult(),Fail{(22,"multipath routing requires an ASCII ALPN without NUL")})

def dial(address: Endpoint.Address, identity: Endpoint.Identity, timeout: U32) -> IO(Quic.ConnectResult()):
  Endpoint.IpAddress{host,port} = address
  Endpoint.PeerKeys{seed,peer,+alpn} = identity
  dial_text(host,port,seed,peer,alpn,timeout,text_alpn(alpn))

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
