import Base
import ../src/endpoint.bend as Endpoint
import ./quic_datagram.bend as Fixture
import ./quic_stream_cancel.bend as Stream
import ./quic_connection_close.bend as Close
import ./quic_datagram_relay_close.bend as Driver
import ./quic_idle_timeout.bend as Idle

def dial_idle(routes: Endpoint.Routes, mode: Maybe<&2,Idle.Mode>) -> IO(Unit):
  match mode:
    case Some{Idle.Configured{value,_,name}}:
      do IO<Unit>:
        owner : Endpoint.Connection() <- IO.try(Endpoint.Connection(),Endpoint.connect_routes_with_idle_timeout(
          routes,
          Endpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.public_key(False{}),Fixture.fixture_alpn()},
          Endpoint.HandshakeTimeouts{5000,5000},value))
        Idle.kept_alive(~Endpoint.Connection(),~Close.Operations{Endpoint.close_with,Endpoint.close_reason,Driver.pump},
          ~Stream.Driver{Driver.step,Driver.apply,Driver.release},owner,name)
    case _:
      IO.die(Unit,1,"expected a UDP port and an idle timeout case")

type Request is Data:
  Route{plan: Endpoint.Routes, setting: String}

def direct(host: String, port: Maybe<&2,U32>, setting: String) -> Maybe<&2,Request>:
  match port:
    case Some{p}:
      Some{Route{Endpoint.DialRoutes{[Endpoint.IpAddress{host,p}],[]},setting}}
    case None{}:
      None{}

def parse(args: List<String>) -> Maybe<&2,Request>:
  match args:
    case [_,host,port,command,setting]:
      Bool.pick(Maybe<&2,Request>,String.eq(command,"route-idle"),direct(host,U32.read(port),setting),None{})
    case [_,url,command,setting]:
      Bool.pick(Maybe<&2,Request>,String.eq(command,"relay-idle"),Some{Route{Endpoint.DialRoutes{[],[url]},setting}},None{})
    case _:
      None{}

def run(request: Maybe<&2,Request>) -> IO(Unit):
  match request:
    case Some{Route{plan,setting}}:
      dial_idle(plan,Idle.setting(setting))
    case None{}:
      IO.die(Unit,1,"expected a direct address or a relay URL and an idle timeout case")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(parse(args))
