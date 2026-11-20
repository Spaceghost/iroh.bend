import Base
import ../src/endpoint.bend as Endpoint
import ../src/quic_datagram.bend as Q
import ../src/quic_nat.bend as Wire
import ../src/quic_close.bend as Close
import ./quic_datagram.bend as Peer
import ./quic_early_listener.bend as Listener
import ./quic_relay_close.bend as RelayTest
import ./quic_datagram_cancel.bend as Datagram
import ./quic_connection_close.bend as CloseTest
import ./quic_idle_timeout.bend as Idle
import ./quic_stream_cancel.bend as Gate

def session_only(status: Q.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,U32 & U32>>)
    -> IO(Q.DatagramConnection):
  match status:
    case (conn,Done{Some{(1,0)}}):
      IO.pure(Q.DatagramConnection,conn)
    case (conn,_):
      Peer.incomplete_stream(conn,"expected resumed TLS without early data")

def quiet(started: Result<&1,&1,U32 & String,Q.DatagramConnection>) -> IO(Unit):
  do IO<Unit>:
    conn : Q.DatagramConnection <- IO.try(Q.DatagramConnection,Q.begin_handshake(started,5000n))
    status : Q.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,U32 & U32>> <- Q.quic_resumption_status(conn)
    ready : Q.DatagramConnection <- session_only(status)
    sent : Q.DatagramConnection <- Peer.send_datagram(1500n,ready,[31,0,255])
    echoed : Q.DatagramConnection <- Peer.receive_reply(1500n,sent,[32,0,255])
    expired : Q.DatagramConnection <- Idle.wait(~Q.DatagramConnection,
      ~CloseTest.Operations{Datagram.close_endpoint,Datagram.endpoint_reason,Q.step_quic_datagram},echoed,8000n)
    reason : Q.DatagramConnection & Close.ReadResult() <- Datagram.endpoint_reason(expired)
    done : Q.DatagramConnection <- Idle.timed_out(Q.DatagramConnection,reason)
    Q.drop_quic_datagram(done)
    IO.print("PASS resumed without early data and reported TimedOut")

# Wait until Iroh has read both early payloads before driving the rest of the handshake.
def resume_received(receipt: (Q.DatagramConnection & U32) & Gate.State) -> IO(Unit):
  match receipt:
    case (early,Gate.Complete{}):
      Peer.await_resumed(early,Peer.AcceptEarly{})
    case ((conn,_),_):
      do IO<Unit>:
        Q.drop_quic_datagram(conn)
        IO.die(Unit,1,"Iroh did not acknowledge the early stream and datagram")

def accept_early(started: Result<&1,&1,U32 & String,Q.DatagramConnection>) -> IO(Unit):
  match started:
    case Fail{(code,message)}:
      IO.die(Unit,code,message)
    case Done{conn}:
      do IO<Unit>:
        early : Q.DatagramConnection & U32 <- Peer.write_early_request(conn)
        receipt : (Q.DatagramConnection & U32) & Gate.State <-
          Gate.gate(Q.DatagramConnection & U32,early,"EARLY sent")
        resume_received(receipt)

def verify(mode: String, result: Result<&1,&1,U32 & String,Q.DatagramConnection>) -> IO(Unit):
  match mode:
    case "quiet":
      quiet(result)
    case "accept":
      accept_early(result)
    case "reject":
      Peer.check_resumed(result,Peer.RejectEarly{},False{})
    case _:
      IO.die(Unit,2,"unknown client resumption mode")

def dial(+host: String, warm: U32, port: U32, +mode: String, idle_ms: Wire.VarInt) -> IO(Unit):
  do IO<Unit>:
    initial : Q.DatagramConnection <- IO.try(Q.DatagramConnection,Q.connect(host,warm,List.replicate(U32,32n,73),
      Peer.public_key(False{}),Peer.fixture_alpn(),5000n))
    ticket : Q.QuicSession <- Peer.wait_session(2000n,initial)
    result : Result<&1,&1,U32 & String,Q.DatagramConnection> <- Q.start_quic_resume_with_idle_timeout(host,port,
      List.replicate(U32,32n,73),Peer.public_key(False{}),Peer.fixture_alpn(),ticket,
      Bool.to_u32(Bool.not(String.eq(mode,"quiet"))),idle_ms)
    verify(mode,result)

def bind(kind: String, host: String, idle_ms: Wire.VarInt)
    -> IO(Result<&1,&1,U32 & String,Q.QuicDatagramListener & U32>):
  match kind:
    case "identity":
      Endpoint.bind_identity_with_idle_timeout(Endpoint.IpAddress{host,0},List.replicate(U32,32n,42),
        Peer.fixture_alpn(),1,idle_ms)
    case "dual":
      Q.bind_dual_quic_identity_with_idle_timeout("::",0,List.replicate(U32,32n,42),Peer.fixture_alpn(),1,idle_ms)
    case _:
      Endpoint.bind_resumable_with_idle_timeout(Endpoint.IpAddress{host,0},
        Endpoint.PeerKeys{List.replicate(U32,32n,42),Peer.public_key(True{}),Peer.fixture_alpn()},idle_ms)

def serve(kind: String, host: String, mode: Listener.RttListenerMode, idle_ms: Wire.VarInt) -> IO(Unit):
  do IO<Unit>:
    bound : Q.QuicDatagramListener & U32 <- IO.try(Q.QuicDatagramListener & U32,bind(kind,host,idle_ms))
    Listener.announce_resumable(bound,"",mode)

def server(kind: String, host: String, mode: String, idle_ms: Wire.VarInt) -> IO(Unit):
  match mode:
    case "accept":
      serve(kind,host,Listener.AcceptTicket{},idle_ms)
    case "warm":
      serve(kind,host,Listener.WarmTicket{},idle_ms)
    case "reject":
      serve(kind,host,Listener.RefuseTicket{},idle_ms)
    case _:
      IO.die(Unit,2,"unknown listener resumption mode")

def authenticated(pair: Endpoint.RelayedListener & Endpoint.Connection())
    -> IO(Endpoint.RelayedListener & Q.DatagramConnection):
  match pair:
    case (listener,(conn,None{})):
      do IO<Endpoint.RelayedListener & Q.DatagramConnection>:
        verified : Q.DatagramConnection <- Listener.verify_peer(conn,Peer.public_key(True{}))
        return (listener,verified)
    case _:
      IO.die(Endpoint.RelayedListener & Q.DatagramConnection,1,"an accepted QUIC connection unexpectedly owns a relay bridge")

def relay_accept(listener: Endpoint.RelayedListener) -> IO(Endpoint.RelayedListener & Q.DatagramConnection):
  do IO<Endpoint.RelayedListener & Q.DatagramConnection>:
    pair : Endpoint.RelayedListener & Endpoint.Connection() <-
      RelayTest.accept(~Endpoint.RelayedListener,~Endpoint.Connection(),~Endpoint.try_accept_relay_identity,listener,15000n)
    authenticated(pair)

def warm_relay(pair: Endpoint.RelayedListener & Q.DatagramConnection) -> IO(Endpoint.RelayedListener):
  (listener,conn) = pair
  do IO<Endpoint.RelayedListener>:
    Listener.warm_session(conn)
    return listener

def finish_relay(pair: Endpoint.RelayedListener & Q.DatagramConnection) -> IO(Unit):
  (listener,conn) = pair
  do IO<Unit>:
    status : Q.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,U32 & U32>> <- Q.quic_resumption_status(conn)
    Listener.server_resume_status(status,True{})
    IO.try(Unit,Endpoint.close_relay_identity(listener))

def serve_relay(listener: Endpoint.RelayedListener, port: U32) -> IO(Unit):
  do IO<Unit>:
    IO.print(U32.show(port))
    first : Endpoint.RelayedListener & Q.DatagramConnection <- relay_accept(listener)
    warm : Endpoint.RelayedListener <- warm_relay(first)
    resumed : Endpoint.RelayedListener & Q.DatagramConnection <- relay_accept(warm)
    finish_relay(resumed)

def direct_relay(result: Endpoint.RelayedListener & U32) -> IO(Unit):
  (listener,port) = result
  serve_relay(listener,port)

def relay(kind: String, url: String, idle_ms: Wire.VarInt) -> IO(Unit):
  match kind:
    case "relay":
      do IO<Unit>:
        owner : Endpoint.RelayedListener <- IO.try(Endpoint.RelayedListener,
          Endpoint.bind_relay_identity_with_idle_timeout(url,List.replicate(U32,32n,42),Peer.fixture_alpn(),1,idle_ms))
        serve_relay(owner,0)
    case _:
      do IO<Unit>:
        bound : Endpoint.RelayedListener & U32 <- IO.try(Endpoint.RelayedListener & U32,
          Endpoint.bind_direct_relay_identity_with_idle_timeout(0,url,List.replicate(U32,32n,42),Peer.fixture_alpn(),1,idle_ms))
        direct_relay(bound)

def pair(a: Maybe<&2,U32>, b: Maybe<&2,U32>, run: U32 -> U32 -> IO(Unit)) -> IO(Unit):
  match a b:
    case Some{x} Some{y}:
      run(x,y)
    case _ _:
      IO.die(Unit,2,"expected unsigned decimal numbers")

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,"client",host,warm,port,mode,hi,lo]:
      pair(U32.read(hi),U32.read(lo),h => l => pair(U32.read(warm),U32.read(port),
        w => p => dial(host,w,p,mode,Wire.Var{h,l})))
    case [_,kind,host,mode,hi,lo]:
      pair(U32.read(hi),U32.read(lo),h => l => server(kind,host,mode,Wire.Var{h,l}))
    case [_,kind,url,hi,lo]:
      pair(U32.read(hi),U32.read(lo),h => l => relay(kind,url,Wire.Var{h,l}))
    case _:
      IO.die(Unit,2,"expected client or server resumption arguments")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
