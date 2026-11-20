import Base
import ../src/endpoint.bend as Endpoint
import ../src/quic_datagram.bend as Q
import ../src/quic_nat.bend as Wire
import ../src/quic_close.bend as Close
import ./quic_datagram.bend as Peer
import ./quic_early_listener.bend as Listener
import ./quic_datagram_cancel.bend as Datagram
import ./quic_connection_close.bend as CloseTest
import ./quic_idle_timeout.bend as Idle

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

def verify(mode: String, result: Result<&1,&1,U32 & String,Q.DatagramConnection>) -> IO(Unit):
  match mode:
    case "quiet":
      quiet(result)
    case "accept":
      Peer.check_resumed(result,Peer.AcceptEarly{},False{})
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

def serve(host: String, mode: Listener.RttListenerMode, idle_ms: Wire.VarInt) -> IO(Unit):
  do IO<Unit>:
    bound : Q.QuicDatagramListener & U32 <- IO.try(Q.QuicDatagramListener & U32,
      Endpoint.bind_resumable_with_idle_timeout(Endpoint.IpAddress{host,0},
        Endpoint.PeerKeys{List.replicate(U32,32n,42),Peer.public_key(True{}),Peer.fixture_alpn()},idle_ms))
    Listener.announce_resumable(bound,"",mode)

def server(host: String, mode: String, idle_ms: Wire.VarInt) -> IO(Unit):
  match mode:
    case "accept":
      serve(host,Listener.AcceptTicket{},idle_ms)
    case "warm":
      serve(host,Listener.WarmTicket{},idle_ms)
    case "reject":
      serve(host,Listener.RefuseTicket{},idle_ms)
    case _:
      IO.die(Unit,2,"unknown listener resumption mode")

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
    case [_,"server",host,mode,hi,lo]:
      pair(U32.read(hi),U32.read(lo),h => l => server(host,mode,Wire.Var{h,l}))
    case _:
      IO.die(Unit,2,"expected client or server resumption arguments")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
