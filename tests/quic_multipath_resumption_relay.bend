import Base
import ../src/endpoint_multipath.bend as Endpoint
import ../src/quic_multipath.bend as Q
import ../src/quic_nat.bend as Wire
import ./quic_multipath_bend.bend as Peer
import ./quic_multipath_listener.bend as Listener
import ./quic_multipath_early_listener.bend as Early
import ./quic_relay_close.bend as RelayTest
import ./quic_resumption_relay.bend as RelayResume

def authenticated(pair: Endpoint.RelayedListener & Q.MultipathConnection) -> IO(Endpoint.RelayedListener & Q.MultipathConnection):
  (owner,conn) = pair
  do IO<Endpoint.RelayedListener & Q.MultipathConnection>:
    verified : Q.MultipathConnection <- Early.verify_peer(conn,Listener.fixture_peer())
    return (owner,verified)

def accept(owner: Endpoint.RelayedListener) -> IO(Endpoint.RelayedListener & Q.MultipathConnection):
  do IO<Endpoint.RelayedListener & Q.MultipathConnection>:
    pair : Endpoint.RelayedListener & Q.MultipathConnection <-
      RelayTest.accept(~Endpoint.RelayedListener,~Q.MultipathConnection,~Endpoint.accept_listener,owner,15000n)
    authenticated(pair)

def resumed(conn: Q.MultipathConnection, accepted: Bool) -> IO(Unit):
  do IO<Unit>:
    status : Q.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <- Q.multipath_resumption_status(conn)
    Early.verify_resumed(status,Bool.to_u32(accepted))

def listen(owner: Endpoint.RelayedListener, port: U32, stage: String) -> IO(Unit):
  RelayResume.listen(~Endpoint.RelayedListener,~Q.MultipathConnection,~accept,~Early.warm,
    ~(conn => accepted => resumed(conn,accepted)),~Endpoint.close_listener,owner,port,stage)

def combined(bound: Endpoint.RelayedListener & U32, stage: String) -> IO(Unit):
  (owner,port) = bound
  listen(owner,port,stage)

def serve(kind: String, url: String, stage: String, idle_ms: Wire.VarInt) -> IO(Unit):
  match kind:
    case "relay":
      do IO<Unit>:
        owner : Endpoint.RelayedListener <- IO.try(Endpoint.RelayedListener,Endpoint.bind_relay_identity_with_idle_timeout(
          url,List.replicate(U32,32n,42),[Peer.text_alpn()],1,idle_ms))
        listen(owner,0,stage)
    case "direct-relay":
      do IO<Unit>:
        bound : Endpoint.RelayedListener & U32 <- IO.try(Endpoint.RelayedListener & U32,
          Endpoint.bind_direct_relay_identity_with_idle_timeout(0,url,List.replicate(U32,32n,42),[Peer.text_alpn()],1,idle_ms))
        combined(bound,stage)
    case _:
      IO.die(Unit,2,"expected a relay or direct-relay listener")

def timeout(kind: String, url: String, stage: String, hi: Maybe<&2,U32>, lo: Maybe<&2,U32>) -> IO(Unit):
  match hi lo:
    case Some{h} Some{l}:
      serve(kind,url,stage,Wire.Var{h,l})
    case _ _:
      IO.die(Unit,2,"expected millisecond timeout words")

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,"rotate",kind,url,stage,hi,lo]:
      timeout(kind,url,stage,U32.read(hi),U32.read(lo))
    case [_,kind,url,hi,lo]:
      timeout(kind,url,"accept",U32.read(hi),U32.read(lo))
    case _:
      IO.die(Unit,2,"expected a listener kind, relay URL and timeout")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
