import Base
import ../src/endpoint_multipath.bend as Endpoint
import ../src/endpoint.bend as BaseEndpoint
import ./quic_multipath_bend.bend as Fixture
import ./quic_stream_cancel.bend as Stream
import ./quic_connection_close.bend as Close
import ./quic_multipath_relay_close.bend as Driver
import ./quic_idle_timeout.bend as Idle
import ./quic_idle_routes.bend as Routes
import ../src/quic_multipath.bend as Quic

def dial_idle(candidate: Routes.Candidate, mode: Maybe<&2,Idle.Mode>) -> IO(Unit):
  match mode:
    case Some{Idle.Configured{value,_,name}}:
      do IO<Unit>:
        owner : Endpoint.Connection() <- IO.try(Endpoint.Connection(),Routes.connect(~Quic.MultipathConnection,
          ~Endpoint.connect_routes_with_idle_timeout,
          ~(plan => identity => timeouts => sources => idle => Endpoint.connect_with_lookup_and_idle_timeout(plan,identity,timeouts,sources,idle)),candidate,
          BaseEndpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.fixture_key(0),Fixture.text_alpn()},
          BaseEndpoint.HandshakeTimeouts{5000,5000},value))
        Idle.kept_alive(~Endpoint.Connection(),~Close.Operations{Endpoint.close_with,Endpoint.close_reason,Driver.pump},
          ~Stream.Driver{Driver.step,Driver.apply,Driver.release},owner,name)
    case _:
      IO.die(Unit,1,"expected a UDP port and an idle timeout case")

def run(request: Maybe<&2,Routes.Request>) -> IO(Unit):
  match request:
    case Some{Routes.Route{candidate,setting}}:
      dial_idle(candidate,Idle.setting(setting))
    case None{}:
      IO.die(Unit,1,"expected a direct address or a relay URL and an idle timeout case")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(Routes.parse(args))
