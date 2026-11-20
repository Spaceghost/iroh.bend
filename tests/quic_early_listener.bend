import Base
import ../src/quic_datagram.bend as Quic
import ./quic_datagram.bend as Fixture

type RttListenerMode is Data:
  WarmTicket{}
  AcceptTicket{}
  RefuseTicket{}

def warm_session(conn: Quic.DatagramConnection) -> IO(Unit):
  do IO<Unit>:
    request : Quic.DatagramConnection <- Fixture.receive_reply(1500n,conn,[13])
    reply : Quic.DatagramConnection <- Fixture.send_datagram(1500n,request,[14])
    Quic.drop_quic_datagram(reply)

def incoming_early_stream(pair: Quic.DatagramConnection & U32, body: List<&2,U32>) -> IO(Quic.DatagramConnection):
  (conn,+stream) = pair
  do IO<Quic.DatagramConnection>:
    read : Quic.DatagramConnection <- Fixture.receive_stream(2500n,conn,stream,body)
    Fixture.server_stream_reply((read,stream),[19,0,255])

def early_server_reply(conn: Quic.DatagramConnection, datagram: List<&2,U32>, stream: List<&2,U32>) -> IO(Unit):
  do IO<Unit>:
    received : Quic.DatagramConnection <- Fixture.receive_reply(1500n,conn,datagram)
    opened : Quic.DatagramConnection & U32 <- Fixture.poll_stream(2500n,received,Fixture.AcceptStream{0})
    replied : Quic.DatagramConnection <- incoming_early_stream(opened,stream)
    sent : Quic.DatagramConnection <- Fixture.send_datagram(1500n,replied,[20,0,255])
    complete : Quic.DatagramConnection <- Fixture.receive_reply(1500n,sent,[21])
    Quic.drop_quic_datagram(complete)

def server_resume_status(
    result: Quic.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,U32 & U32>>, accepted: Bool) -> IO(Unit):
  match result accepted:
    case (conn,Done{Some{(1,1)}}) True{}:
      do IO<Unit>:
        early_server_reply(conn,[15,0,255],[17,0,255])
        IO.print("PASS Bend accepted Iroh 0-RTT streams and datagrams")
    case (conn,Done{Some{(0,2)}}) False{}:
      do IO<Unit>:
        early_server_reply(conn,[16,0,255],[18,0,255])
        IO.print("PASS Bend rejected an unrelated ticket and accepted only the explicit 1-RTT retries")
    case (conn,_) _:
      do IO<Unit>:
        Quic.drop_quic_datagram(conn)
        IO.die(Unit,1,"Bend listener reported an unexpected resumption status")

def resumed_connection(pair: Quic.QuicDatagramListener & Quic.DatagramConnection, accepted: Bool) -> IO(Unit):
  (listener,conn) = pair
  do IO<Unit>:
    Quic.close_shared_quic(listener)
    result : Quic.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,U32 & U32>> <-
      Quic.quic_resumption_status(conn)
    server_resume_status(result,accepted)

def serve_resumption(first: Quic.QuicDatagramListener & Quic.DatagramConnection, mode: RttListenerMode) -> IO(Unit):
  match first mode:
    case (listener,conn) WarmTicket{}:
      do IO<Unit>:
        Quic.close_shared_quic(listener)
        warm_session(conn)
    case (listener,conn) AcceptTicket{}:
      do IO<Unit>:
        warm_session(conn)
        second : Quic.QuicDatagramListener & Quic.DatagramConnection <- Fixture.server_accept(12000n,listener)
        resumed_connection(second,True{})
    case _ RefuseTicket{}:
      resumed_connection(first,False{})

def announce_resumable(bound: Quic.QuicDatagramListener & U32, prefix: String, mode: RttListenerMode) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    IO.print(String.append(prefix,U32.show(port)))
    first : Quic.QuicDatagramListener & Quic.DatagramConnection <- Fixture.server_accept(15000n,listener)
    serve_resumption(first,mode)

def listen_resumable(host: String, prefix: String, mode: RttListenerMode) -> IO(Unit):
  do IO<Unit>:
    bound : Quic.QuicDatagramListener & U32 <- IO.try(Quic.QuicDatagramListener & U32,
      Quic.bind_resumable_quic(host,0,List.replicate(U32,32n,42),Fixture.public_key(True{}),Fixture.fixture_alpn()))
    announce_resumable(bound,prefix,mode)

def choose_resumable(mode: Maybe<&2,U32>) -> IO(Unit):
  match mode:
    case Some{0}:
      listen_resumable("127.0.0.1","127.0.0.1:",AcceptTicket{})
    case Some{1}:
      listen_resumable("127.0.0.1","127.0.0.1:",WarmTicket{})
    case Some{2}:
      listen_resumable("127.0.0.1","127.0.0.1:",RefuseTicket{})
    case Some{3}:
      listen_resumable("::1","[::1]:",AcceptTicket{})
    case Some{4}:
      listen_resumable("::1","[::1]:",WarmTicket{})
    case Some{5}:
      listen_resumable("::1","[::1]:",RefuseTicket{})
    case _:
      IO.die(Unit,2,"expected a resumption listener mode")

def confirmed_peer(conn: Quic.DatagramConnection, same: Bool) -> IO(Quic.DatagramConnection):
  match same:
    case True{}:
      IO.pure(Quic.DatagramConnection,conn)
    case False{}:
      do IO<Quic.DatagramConnection>:
        Quic.drop_quic_datagram(conn)
        IO.die(Quic.DatagramConnection,1,"authenticated peer identity differs")

def peer_result(pair: Quic.DatagramConnection & Result<&1,&1,U32 & String,List<&2,U32>>,
    expected: List<&2,U32>) -> IO(Quic.DatagramConnection):
  match pair:
    case (conn,Done{key}):
      confirmed_peer(conn,Fixture.same_bytes(expected,key))
    case (conn,Fail{(_,message)}):
      do IO<Quic.DatagramConnection>:
        Quic.drop_quic_datagram(conn)
        IO.die(Quic.DatagramConnection,1,message)

def verify_peer(conn: Quic.DatagramConnection, expected: List<&2,U32>) -> IO(Quic.DatagramConnection):
  do IO<Quic.DatagramConnection>:
    identity : Quic.DatagramConnection & Result<&1,&1,U32 & String,List<&2,U32>> <- Quic.quic_remote_id(conn)
    peer_result(identity,expected)

def finish_identity_resume(pair: Quic.QuicDatagramListener & Quic.DatagramConnection,
    key: List<&2,U32>) -> IO(Quic.QuicDatagramListener):
  (listener,conn) = pair
  do IO<Quic.QuicDatagramListener>:
    authenticated : Quic.DatagramConnection <- verify_peer(conn,key)
    status : Quic.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,U32 & U32>> <-
      Quic.quic_resumption_status(authenticated)
    server_resume_status(status,True{})
    return listener

def identity_peer(pair: Quic.QuicDatagramListener & Quic.DatagramConnection, +key: List<&2,U32>)
    -> IO(Quic.QuicDatagramListener):
  (listener,conn) = pair
  do IO<Quic.QuicDatagramListener>:
    authenticated : Quic.DatagramConnection <- verify_peer(conn,key)
    warm_session(authenticated)
    resume : Quic.QuicDatagramListener & Quic.DatagramConnection <- Fixture.server_accept(12000n,listener)
    finish_identity_resume(resume,key)

def identity_sequence(keys: List<&2,List<&2,U32>>, listener: Quic.QuicDatagramListener) -> IO(Unit):
  match keys:
    case Nil{}:
      do IO<Unit>:
        Quic.close_shared_quic(listener)
        IO.print("PASS listener reported both authenticated peers before and after resumption")
    case Con{key,rest}:
      do IO<Unit>:
        incoming : Quic.QuicDatagramListener & Quic.DatagramConnection <- Fixture.server_accept(12000n,listener)
        next : Quic.QuicDatagramListener <- identity_peer(incoming,key)
        identity_sequence(rest,next)

def announce_identity(bound: Quic.QuicDatagramListener & U32) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    identity_sequence([Fixture.public_key(True{}),[53,60,138,127,238,202,56,178,196,83,110,11,210,88,111,219,
     24,208,112,229,14,5,159,29,67,248,191,239,185,122,124,225]],listener)

def listen_identity(host: String) -> IO(Unit):
  do IO<Unit>:
    bound : Quic.QuicDatagramListener & U32 <- IO.try(Quic.QuicDatagramListener & U32,
      Quic.bind_quic_identity(host,0,List.replicate(U32,32n,42),Fixture.fixture_alpn(),1))
    announce_identity(bound)

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,host,"identity"]:
      listen_identity(host)
    case Con{_,Con{mode,Nil{}}}:
      choose_resumable(U32.read(mode))
    case _:
      IO.die(Unit,2,"expected a resumption listener mode")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
