import Base
import ../src/quic_multipath.bend as Quic
import ./quic_multipath_bend.bend as Fixture
import ./quic_multipath_listener.bend as Listener

def check_fin(pair: Quic.MultipathConnection & Quic.MultipathRead, stream: U32) -> IO(Quic.MultipathConnection):
  match pair:
    case (conn,Quic.MultipathReadFin{}):
      do IO<Quic.MultipathConnection>:
        written : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <-
          Quic.write_multipath_stream(conn,stream,[19,0,255],1)
        value : Quic.MultipathConnection & U32 <- Fixture.ok(U32,written)
        return Fixture.stepped(value)
    case (conn,_):
      Fixture.reject(Quic.MultipathConnection,conn,1,"expected early stream FIN")

def check_payload(conn: Quic.MultipathConnection, +stream: U32, matches: Bool) -> IO(Quic.MultipathConnection):
  match matches:
    case True{}:
      do IO<Quic.MultipathConnection>:
        reply : Quic.MultipathConnection & Result<&1,&1,U32 & String,Quic.MultipathRead> <- Quic.read_multipath_stream(conn,stream,1)
        fin : Quic.MultipathConnection & Quic.MultipathRead <- Fixture.ok(Quic.MultipathRead,reply)
        check_fin(fin,stream)
    case False{}:
      Fixture.reject(Quic.MultipathConnection,conn,1,"unexpected stream payload")

def check_stream(pair: Quic.MultipathConnection & Quic.MultipathRead, +stream: U32, expected: U32) -> IO(Quic.MultipathConnection):
  match pair expected:
    case (conn,Quic.MultipathReadBytes{[byte,0,255]}) expected:
      check_payload(conn,stream,U32.is_eq(byte,expected))
    case (conn,_) _:
      Fixture.reject(Quic.MultipathConnection,conn,1,"unexpected stream payload")

def read_reply(pair: Quic.MultipathConnection & U32, expected: U32) -> IO(Quic.MultipathConnection):
  (conn,+id) = pair
  do IO<Quic.MultipathConnection>:
    reply : Quic.MultipathConnection & Result<&1,&1,U32 & String,Quic.MultipathRead> <- Quic.read_multipath_stream(conn,id,3)
    body : Quic.MultipathConnection & Quic.MultipathRead <- Fixture.ok(Quic.MultipathRead,reply)
    check_stream(body,id,expected)

def exchange(conn: Quic.MultipathConnection, datagram: U32, stream: U32) -> IO(Unit):
  do IO<Unit>:
    request : Quic.MultipathConnection <- Fixture.read_datagram(3000n,conn,[datagram,0,255])
    incoming : Quic.MultipathConnection & U32 <- Listener.incoming(3000n,request,0)
    replied : Quic.MultipathConnection <- read_reply(incoming,stream)
    sent : Quic.MultipathConnection <- Fixture.send_datagram(1500n,replied,[20,0,255])
    confirmed : Quic.MultipathConnection <- Fixture.read_datagram(1500n,sent,[21])
    Quic.close_multipath(confirmed)

def verify_early(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>, resumed: U32) -> IO(Unit):
  match pair resumed:
    case (conn,Done{Some{1}}) 1:
      do IO<Unit>:
        exchange(conn,15,17)
        IO.print("PASS listener delivered the authenticated 0-RTT stream and datagram")
    case (conn,Done{Some{0}}) 0:
      do IO<Unit>:
        exchange(conn,16,18)
        IO.print("PASS fresh listener accepted only the 1-RTT retry")
    case (conn,_) _:
      Fixture.reject(Unit,conn,1,"unexpected listener early-data status")

def check_resumption(conn: Quic.MultipathConnection, expected: U32, matches: Bool) -> IO(Unit):
  match matches:
    case True{}:
      do IO<Unit>:
        early : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <- Quic.multipath_early_status(conn)
        verify_early(early,expected)
    case False{}:
      Fixture.reject(Unit,conn,1,"unexpected listener resumption status")

def verify_resumed(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>, +expected: U32) -> IO(Unit):
  match pair:
    case (conn,Done{Some{resumed}}):
      check_resumption(conn,expected,U32.is_eq(resumed,expected))
    case (conn,_):
      Fixture.reject(Unit,conn,1,"resumption status unavailable")

def finish(pair: Quic.MultipathListener & Quic.MultipathConnection, expected: U32) -> IO(Unit):
  (listener,conn) = pair
  do IO<Unit>:
    Quic.close_multipath_listener(listener)
    status : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <- Quic.multipath_resumption_status(conn)
    verify_resumed(status,expected)

def warm(conn: Quic.MultipathConnection) -> IO(Unit):
  do IO<Unit>:
    request : Quic.MultipathConnection <- Fixture.read_datagram(3000n,conn,[13])
    replied : Quic.MultipathConnection <- Fixture.send_datagram(3000n,request,[14])
    flushed : Quic.MultipathConnection <- Fixture.step(replied)
    Quic.close_multipath(flushed)

def serve(pair: Quic.MultipathListener & Quic.MultipathConnection, mode: String) -> IO(Unit):
  match pair mode:
    case (listener,conn) "warm":
      do IO<Unit>:
        Quic.close_multipath_listener(listener)
        warm(conn)
    case (listener,conn) "reuse":
      do IO<Unit>:
        warm(conn)
        resumed : Quic.MultipathListener & Quic.MultipathConnection <- Listener.accept(9000n,listener)
        finish(resumed,1)
    case pair _:
      finish(pair,0)

def announce(pair: Quic.MultipathListener & U32, mode: String) -> IO(Unit):
  (listener,port) = pair
  do IO<Unit>:
    IO.print(U32.show(port))
    incoming : Quic.MultipathListener & Quic.MultipathConnection <- Listener.accept(9000n,listener)
    serve(incoming,mode)

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,host,mode]:
      do IO<Unit>:
        listener : Quic.MultipathListener & U32 <- IO.try(Quic.MultipathListener & U32,
          Quic.bind_resumable_multipath(host,0,List.replicate(U32,32n,42),Listener.fixture_peer(),Fixture.text_alpn()))
        announce(listener,mode)
    case _:
      IO.die(Unit,2,"expected a host and resumption mode")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
