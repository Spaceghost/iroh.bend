import Base
import ../src/endpoint_multipath.bend as Endpoint
import ../src/quic_multipath.bend as Q
import ../src/quic_nat.bend as Wire
import ./quic_multipath_bend.bend as Peer
import ./quic_multipath_listener.bend as Listener
import ./quic_multipath_early_listener.bend as Early
import ./quic_relay_close.bend as RelayTest

def accept(owner: Endpoint.RelayedListener) -> IO(Endpoint.RelayedListener & Q.MultipathConnection):
  RelayTest.accept(~Endpoint.RelayedListener,~Q.MultipathConnection,~Endpoint.accept_listener,owner,15000n)

def exchange(pair: Endpoint.RelayedListener & Q.MultipathConnection, serve: Q.MultipathConnection -> IO(Unit))
    -> IO(Endpoint.RelayedListener):
  (owner,conn) = pair
  do IO<Endpoint.RelayedListener>:
    authenticated : Q.MultipathConnection <- Early.verify_peer(conn,Listener.fixture_peer())
    serve(authenticated)
    return owner

def resumed(conn: Q.MultipathConnection) -> IO(Unit):
  do IO<Unit>:
    status : Q.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <- Q.multipath_resumption_status(conn)
    Early.verify_resumed(status,1)

def listen(owner: Endpoint.RelayedListener, port: U32) -> IO(Unit):
  do IO<Unit>:
    IO.print(U32.show(port))
    first : Endpoint.RelayedListener & Q.MultipathConnection <- accept(owner)
    warm : Endpoint.RelayedListener <- exchange(first,Early.warm)
    second : Endpoint.RelayedListener & Q.MultipathConnection <- accept(warm)
    done : Endpoint.RelayedListener <- exchange(second,resumed)
    IO.try(Unit,Endpoint.close_listener(done))

def combined(bound: Endpoint.RelayedListener & U32) -> IO(Unit):
  (owner,port) = bound
  listen(owner,port)

def serve(kind: String, url: String, idle_ms: Wire.VarInt) -> IO(Unit):
  match kind:
    case "relay":
      do IO<Unit>:
        owner : Endpoint.RelayedListener <- IO.try(Endpoint.RelayedListener,Endpoint.bind_relay_identity_with_idle_timeout(
          url,List.replicate(U32,32n,42),[Peer.text_alpn()],1,idle_ms))
        listen(owner,0)
    case "direct-relay":
      do IO<Unit>:
        bound : Endpoint.RelayedListener & U32 <- IO.try(Endpoint.RelayedListener & U32,
          Endpoint.bind_direct_relay_identity_with_idle_timeout(0,url,List.replicate(U32,32n,42),[Peer.text_alpn()],1,idle_ms))
        combined(bound)
    case _:
      IO.die(Unit,2,"expected a relay or direct-relay listener")

def timeout(kind: String, url: String, hi: Maybe<&2,U32>, lo: Maybe<&2,U32>) -> IO(Unit):
  match hi lo:
    case Some{h} Some{l}:
      serve(kind,url,Wire.Var{h,l})
    case _ _:
      IO.die(Unit,2,"expected millisecond timeout words")

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,kind,url,hi,lo]:
      timeout(kind,url,U32.read(hi),U32.read(lo))
    case _:
      IO.die(Unit,2,"expected a listener kind, relay URL and timeout")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
