import Base
import ../src/quic_multipath.bend as Quic
import ../src/quic_nat.bend as Wire
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

def identity_result(pair: Quic.MultipathConnection & List<&2,U32>, expected: List<&2,U32>) -> IO(Quic.MultipathConnection):
  (conn,key) = pair
  Fixture.checked_datagram(conn,Fixture.same_bytes(key,expected))

def verify_peer(conn: Quic.MultipathConnection, expected: List<&2,U32>) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>> <- Quic.multipath_remote_id(conn)
    identity : Quic.MultipathConnection & List<&2,U32> <- Fixture.ok(List<&2,U32>,result)
    identity_result(identity,expected)

def authenticated(pair: Quic.MultipathListener & Quic.MultipathConnection)
    -> IO(Quic.MultipathListener & Quic.MultipathConnection):
  (listener,conn) = pair
  do IO<Quic.MultipathListener & Quic.MultipathConnection>:
    verified : Quic.MultipathConnection <- verify_peer(conn,Listener.fixture_peer())
    return (listener,verified)

def accept_verified(listener: Quic.MultipathListener) -> IO(Quic.MultipathListener & Quic.MultipathConnection):
  do IO<Quic.MultipathListener & Quic.MultipathConnection>:
    pair : Quic.MultipathListener & Quic.MultipathConnection <- Listener.accept(9000n,listener)
    authenticated(pair)

def serve(pair: Quic.MultipathListener & Quic.MultipathConnection, mode: String) -> IO(Unit):
  match pair mode:
    case (listener,conn) "warm":
      do IO<Unit>:
        Quic.close_multipath_listener(listener)
        warm(conn)
    case (listener,conn) "reuse":
      do IO<Unit>:
        warm(conn)
        resumed : Quic.MultipathListener & Quic.MultipathConnection <- accept_verified(listener)
        finish(resumed,1)
    case pair _:
      finish(pair,0)

def announce(pair: Quic.MultipathListener & U32, mode: String) -> IO(Unit):
  (listener,port) = pair
  do IO<Unit>:
    IO.print(U32.show(port))
    incoming : Quic.MultipathListener & Quic.MultipathConnection <- accept_verified(listener)
    serve(incoming,mode)

def finish_identity_resume(pair: Quic.MultipathListener & Quic.MultipathConnection,
    key: List<&2,U32>) -> IO(Quic.MultipathListener):
  (listener,conn) = pair
  do IO<Quic.MultipathListener>:
    authenticated : Quic.MultipathConnection <- verify_peer(conn,key)
    status : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <-
      Quic.multipath_resumption_status(authenticated)
    verify_resumed(status,1)
    return listener

def identity_peer(pair: Quic.MultipathListener & Quic.MultipathConnection, +key: List<&2,U32>) -> IO(Quic.MultipathListener):
  (listener,conn) = pair
  do IO<Quic.MultipathListener>:
    authenticated : Quic.MultipathConnection <- verify_peer(conn,key)
    warm(authenticated)
    resumed : Quic.MultipathListener & Quic.MultipathConnection <- Listener.accept(9000n,listener)
    finish_identity_resume(resumed,key)

def identity_sequence(keys: List<&2,List<&2,U32>>, listener: Quic.MultipathListener) -> IO(Unit):
  match keys:
    case Nil{}:
      do IO<Unit>:
        Quic.close_multipath_listener(listener)
        IO.print("PASS listener reported both authenticated peers before and after resumption")
    case Con{key,rest}:
      do IO<Unit>:
        incoming : Quic.MultipathListener & Quic.MultipathConnection <- Listener.accept(9000n,listener)
        next : Quic.MultipathListener <- identity_peer(incoming,key)
        identity_sequence(rest,next)

def announce_identity(bound: Quic.MultipathListener & U32) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    identity_sequence([Listener.fixture_peer(),[53,60,138,127,238,202,56,178,196,83,110,11,210,88,111,219,
     24,208,112,229,14,5,159,29,67,248,191,239,185,122,124,225]],listener)

def listen_identity(host: String) -> IO(Unit):
  do IO<Unit>:
    bound : Quic.MultipathListener & U32 <- IO.try(Quic.MultipathListener & U32,
      Quic.bind_multipath_identity(host,0,List.replicate(U32,32n,42),[Fixture.text_alpn()],1))
    announce_identity(bound)

def configured(kind: String, host: String, idle_ms: Wire.VarInt)
    -> IO(Result<&1,&1,U32 & String,Quic.MultipathListener & U32>):
  match kind:
    case "server":
      Quic.bind_resumable_multipath_with_idle_timeout(host,0,List.replicate(U32,32n,42),Listener.fixture_peer(),Fixture.text_alpn(),idle_ms)
    case "identity":
      Quic.bind_multipath_identity_with_idle_timeout(host,0,List.replicate(U32,32n,42),[Fixture.text_alpn()],1,idle_ms)
    case "dual":
      Quic.bind_dual_multipath_identity_with_idle_timeout("::",0,List.replicate(U32,32n,42),[Fixture.text_alpn()],1,idle_ms)
    case _:
      IO.pure(Result<&1,&1,U32 & String,Quic.MultipathListener & U32>,Fail{(22,"unknown listener kind")})

def announce_configured(bound: Quic.MultipathListener & U32, mode: String) -> IO(Unit):
  match bound mode:
    case pair "accept":
      announce(pair,"reuse")
    case pair "warm":
      announce(pair,"warm")
    case pair "reject":
      announce(pair,"fresh")
    case (listener,_) _:
      do IO<Unit>:
        Quic.close_multipath_listener(listener)
        IO.die(Unit,2,"unknown listener resumption mode")

def configured_listener(kind: String, host: String, mode: String, hi: Maybe<&2,U32>, lo: Maybe<&2,U32>) -> IO(Unit):
  match hi lo:
    case Some{h} Some{l}:
      do IO<Unit>:
        bound : Quic.MultipathListener & U32 <- IO.try(Quic.MultipathListener & U32,configured(kind,host,Wire.Var{h,l}))
        announce_configured(bound,mode)
    case _ _:
      IO.die(Unit,2,"expected millisecond timeout words")

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,kind,host,mode,hi,lo]:
      configured_listener(kind,host,mode,U32.read(hi),U32.read(lo))
    case [_,host,"identity"]:
      listen_identity(host)
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
