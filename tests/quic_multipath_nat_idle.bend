import Base
import ../src/endpoint.bend as BaseEndpoint
import ../src/endpoint_multipath.bend as Endpoint
import ../src/quic_multipath.bend as Q
import ../src/quic_multipath_nat.bend as Nat
import ../src/quic_nat.bend as Wire
import ./quic_connection_close.bend as Close
import ./quic_idle_timeout.bend as Idle
import ./quic_multipath_bend.bend as Peer
import ./quic_multipath_relay_close.bend as Driver
import ./quic_relay_close.bend as Listener
import ./quic_stream_cancel.bend as Stream

def seed() -> List<&2,U32>:
  List.replicate(U32,32n,73)

def identity() -> BaseEndpoint.Identity:
  BaseEndpoint.PeerKeys{seed(),Peer.fixture_key(0),Peer.text_alpn()}

def check_parameter(conn: Q.MultipathConnection, parameter: Wire.ParameterResult) -> IO(Q.MultipathConnection):
  match parameter:
    case Wire.ParameterLimit{32}:
      IO.pure(Q.MultipathConnection,conn)
    case _:
      Peer.reject(Q.MultipathConnection,conn,1,"Iroh did not advertise its NAT traversal limit of 32")

def check_parameters(reply: Q.MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>>)
    -> IO(Q.MultipathConnection):
  match reply:
    case (conn,Done{bytes}):
      check_parameter(conn,Wire.read_parameters(bytes))
    case (conn,Fail{(code,message)}):
      Peer.reject(Q.MultipathConnection,conn,code,message)

def exchange(owner: Endpoint.Connection(), name: String) -> IO(Unit):
  (conn,bridge) = owner
  do IO<Unit>:
    params : Q.MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>> <- Q.peer_multipath_parameters(conn)
    verified : Q.MultipathConnection <- check_parameters(params)
    Idle.kept_alive(~Endpoint.Connection(),~Close.Operations{Endpoint.close_with,Endpoint.close_reason,Driver.pump},
      ~Stream.Driver{Driver.step,Driver.apply,Driver.release},(verified,bridge),name)

def plain(pair: Nat.Connection()) -> Endpoint.Connection():
  (conn,_) = pair
  (conn,None{})

def relayed(owner: Endpoint.NatRelayConnection()) -> Endpoint.Connection():
  ((conn,_),bridge) = owner
  (conn,bridge)

def routed(owner: Endpoint.RoutedConnection) -> Endpoint.Connection():
  Endpoint.Routed{conn,_,_} = owner
  conn

def dial_routes(routes: BaseEndpoint.Routes, idle: Wire.VarInt, name: String) -> IO(Unit):
  do IO<Unit>:
    owner : Endpoint.RoutedConnection <- IO.try(Endpoint.RoutedConnection,
      Endpoint.connect_routed_with_idle_timeout(routes,identity(),BaseEndpoint.HandshakeTimeouts{4000,6000},idle))
    exchange(routed(owner),name)

def dial_direct(host: String, port: U32, idle: Wire.VarInt, name: String) -> IO(Unit):
  do IO<Unit>:
    owner : Nat.Connection() <- IO.try(Nat.Connection(),
      Endpoint.connect_nat_direct_with_idle_timeout(BaseEndpoint.IpAddress{host,port},identity(),5000,64,idle))
    exchange(plain(owner),name)

def dial_relay(url: String, idle: Wire.VarInt, name: String) -> IO(Unit):
  do IO<Unit>:
    owner : Endpoint.NatRelayConnection() <- IO.try(Endpoint.NatRelayConnection(),
      Endpoint.connect_nat_relay_using_with_idle_timeout(url,identity(),BaseEndpoint.IpAddress{"127.0.0.1",0},
        6000,64,None{},idle))
    exchange(relayed(owner),name)

def serve_direct(accepted: Nat.NatListener() & Nat.ListenerConnection(), name: String) -> IO(Unit):
  (listener,(conn,_)) = accepted
  do IO<Unit>:
    exchange((conn,None{}),name)
    Nat.close_listener(listener)

def announce_direct(bound: Nat.NatListener() & U32, name: String) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    accepted : Nat.NatListener() & Nat.ListenerConnection() <-
      Listener.accept(~Nat.NatListener(),~Nat.ListenerConnection(),~Nat.accept_listener,listener,9000n)
    serve_direct(accepted,name)

def listen_direct(host: String, idle: Wire.VarInt, name: String) -> IO(Unit):
  do IO<Unit>:
    bound : Nat.NatListener() & U32 <- IO.try(Nat.NatListener() & U32,
      Nat.bind_listener_with_idle_timeout(host,0,seed(),Peer.fixture_key(0),[Peer.text_alpn()],64,idle))
    announce_direct(bound,name)

def serve_relay(accepted: Endpoint.NatRelayedListener() & Nat.ListenerConnection(), name: String) -> IO(Unit):
  (listener,(conn,_)) = accepted
  do IO<Unit>:
    exchange((conn,None{}),name)
    IO.try(Unit,Endpoint.close_nat_listener(listener))

def announce_relay(bound: Endpoint.NatRelayedListener() & U32, name: String) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    accepted : Endpoint.NatRelayedListener() & Nat.ListenerConnection() <-
      Listener.accept(~Endpoint.NatRelayedListener(),~Nat.ListenerConnection(),~Endpoint.accept_nat_listener,listener,9000n)
    serve_relay(accepted,name)

def listen_relay(url: String, idle: Wire.VarInt, name: String) -> IO(Unit):
  do IO<Unit>:
    bound : Endpoint.NatRelayedListener() & U32 <- IO.try(Endpoint.NatRelayedListener() & U32,
      Endpoint.bind_nat_listener_with_idle_timeout(0,url,seed(),[Peer.text_alpn()],0,64,idle))
    announce_relay(bound,name)

def with_port(port: Maybe<&2,U32>, run: U32 -> IO(Unit)) -> IO(Unit):
  match port:
    case Some{value}:
      run(value)
    case None{}:
      IO.die(Unit,2,"expected a numeric UDP port")

def run(args: List<String>, idle: Wire.VarInt, name: String) -> IO(Unit):
  match args:
    case ["direct",host,port]:
      with_port(U32.read(port),p => dial_direct(host,p,idle,name))
    case ["route",host,port]:
      with_port(U32.read(port),p => dial_routes(BaseEndpoint.DialRoutes{[BaseEndpoint.IpAddress{host,p}],[]},idle,name))
    case ["relay",url]:
      dial_relay(url,idle,name)
    case ["relay-route",url]:
      dial_routes(BaseEndpoint.DialRoutes{[],[url]},idle,name)
    case ["listen",host]:
      listen_direct(host,idle,name)
    case ["listen-relay",url]:
      listen_relay(url,idle,name)
    case _:
      IO.die(Unit,2,"expected a NAT transport mode and address")

def setting(mode: Maybe<&2,Idle.Mode>, args: List<String>) -> IO(Unit):
  match mode:
    case Some{Idle.Configured{value,_,name}}:
      run(args,value,name)
    case _:
      IO.die(Unit,2,"expected a configured idle timeout case")

def command(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{case_name,modes}}:
      setting(Idle.setting(case_name),modes)
    case _:
      IO.die(Unit,2,"expected an idle timeout case and NAT transport mode")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    command(args)
