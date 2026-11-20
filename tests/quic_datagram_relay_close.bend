import Base
import ../src/endpoint.bend as Endpoint
import ../src/quic_datagram.bend as Q
import ./quic_datagram_cancel.bend as Streams
import ./quic_datagram.bend as Fixture
import ./quic_stream_cancel.bend as Stream
import ./quic_connection_close.bend as Close
import ./quic_relay_close.bend as Test

def pump(owner: Endpoint.Connection()) -> IO(Endpoint.Connection() & Result<&1,&1,U32 & String,U32>):
  Endpoint.use_connection(Result<&1,&1,U32 & String,U32>,owner,Q.step_quic_datagram)

def step(owner: Endpoint.Connection()) -> IO(Endpoint.Connection()):
  do IO<Endpoint.Connection()>:
    raw : Endpoint.Connection() & Result<&1,&1,U32 & String,U32> <- pump(owner)
    Test.ready(Endpoint.Connection(),raw)

def apply(owner: Endpoint.Connection(), id: U32, action: Stream.Action) -> Stream.Reply(Endpoint.Connection()):
  Endpoint.use_connection(Stream.State,owner,c => Streams.perform(c,id,action))

def release(owner: Endpoint.Connection()) -> IO(Unit):
  IO.try(Unit,Endpoint.disconnect(owner))

def exchange(owner: Endpoint.Connection(), send: Bool, id: U32) -> IO(Unit):
  Test.exchange(~Endpoint.Connection(),~Close.Operations{Endpoint.close_with,Endpoint.close_reason,pump},
    ~Stream.Driver{step,apply,release},owner,send,id)

def dial(url: String, send: Bool, id: U32) -> IO(Unit):
  do IO<Unit>:
    owner : Endpoint.Connection() <- IO.try(Endpoint.Connection(),Endpoint.connect_routes(
      Endpoint.DialRoutes{[],[url]},Endpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.public_key(False{}),Fixture.fixture_alpn()},
      Endpoint.HandshakeTimeouts{4000,6000}))
    connected : Endpoint.Connection() <- Test.check_route(Q.DatagramConnection,owner)
    exchange(connected,send,id)

def serve(pair: Endpoint.RelayedListener & Endpoint.Connection(), send: Bool, id: U32) -> IO(Unit):
  (listener,conn) = pair
  do IO<Unit>:
    exchange(conn,send,id)
    IO.try(Unit,Endpoint.close_relay_identity(listener))

def listen(url: String, send: Bool, id: U32) -> IO(Unit):
  do IO<Unit>:
    listener : Endpoint.RelayedListener <- IO.try(Endpoint.RelayedListener,
      Endpoint.bind_relay_identity(url,List.replicate(U32,32n,73),Fixture.fixture_alpn(),0))
    IO.print("READY relay")
    pair : Endpoint.RelayedListener & Endpoint.Connection() <-
      Test.accept(~Endpoint.RelayedListener,~Endpoint.Connection(),~Endpoint.try_accept_relay_identity,listener,9000n)
    serve(pair,send,id)

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    Test.command(args,listen,dial)
