import Base
import ../src/endpoint_multipath.bend as Endpoint
import ../src/endpoint.bend as BaseEndpoint
import ./quic_multipath_bend.bend as Fixture
import ./quic_stream_cancel.bend as Stream
import ./quic_connection_close.bend as Close
import ./quic_multipath_relay_close.bend as Driver
import ./quic_idle_timeout.bend as Idle

def dial_idle(routes: BaseEndpoint.Routes, mode: Maybe<&2,Idle.Mode>) -> IO(Unit):
  match mode:
    case Some{Idle.Configured{value,_,name}}:
      do IO<Unit>:
        owner : Endpoint.Connection() <- IO.try(Endpoint.Connection(),Endpoint.connect_routes_with_idle_timeout(
          routes,
          BaseEndpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.fixture_key(0),Fixture.text_alpn()},
          BaseEndpoint.HandshakeTimeouts{5000,5000},value))
        Idle.kept_alive(~Endpoint.Connection(),~Close.Operations{Endpoint.close_with,Endpoint.close_reason,Driver.pump},
          ~Stream.Driver{Driver.step,Driver.apply,Driver.release},owner,name)
    case _:
      IO.die(Unit,1,"expected a UDP port and an idle timeout case")

type Request is Data:
  Route{plan: BaseEndpoint.Routes, setting: String}

def direct(host: String, port: Maybe<&2,U32>, setting: String) -> Maybe<&2,Request>:
  match port:
    case Some{p}:
      Some{Route{BaseEndpoint.DialRoutes{[BaseEndpoint.IpAddress{host,p}],[]},setting}}
    case None{}:
      None{}

def parse(args: List<String>) -> Maybe<&2,Request>:
  match args:
    case [_,host,port,command,setting]:
      Bool.pick(Maybe<&2,Request>,String.eq(command,"route-idle"),direct(host,U32.read(port),setting),None{})
    case [_,url,command,setting]:
      Bool.pick(Maybe<&2,Request>,String.eq(command,"relay-idle"),Some{Route{BaseEndpoint.DialRoutes{[],[url]},setting}},None{})
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
