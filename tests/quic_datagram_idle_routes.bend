import Base
import ../src/endpoint.bend as Endpoint
import ./quic_datagram.bend as Fixture
import ./quic_stream_cancel.bend as Stream
import ./quic_connection_close.bend as Close
import ./quic_datagram_relay_close.bend as Driver
import ./quic_idle_timeout.bend as Idle
import ./quic_idle_routes.bend as Routes
import ../src/quic_datagram.bend as Quic

def dial_idle(candidate: Routes.Candidate, mode: Maybe<&2,Idle.Mode>) -> IO(Unit):
  match mode:
    case Some{Idle.Configured{value,_,name}}:
      do IO<Unit>:
        owner : Endpoint.Connection() <- IO.try(Endpoint.Connection(),Routes.connect(~Quic.DatagramConnection,
          ~Endpoint.connect_routes_with_idle_timeout,
          ~(plan => identity => timeouts => sources => idle => Endpoint.connect_with_lookup_and_idle_timeout(plan,identity,timeouts,sources,idle)),candidate,
          Endpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.public_key(False{}),Fixture.fixture_alpn()},
          Endpoint.HandshakeTimeouts{5000,5000},value))
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
