import Base
import ../src/direct.bend as Direct
import ../src/relay_quic.bend as Path
import ./direct.bend as Fixture
import ./quic_streams.bend as Stream

def serve_path(listener: Direct.QuicListener, path: Path.Bridge & U32) -> IO(Unit):
  (bridge,_) = path
  do IO<Unit>:
    IO.print("relay QUIC listener ready")
    request : Direct.QuicStream & List<&2,U32> <- IO.try(Direct.QuicStream & List<&2,U32>,Direct.accept(listener,1024))
    Fixture.echo(request)
    IO.try(Unit,Path.stop(bridge))

def answer(bound: Direct.QuicListener & U32, url: String) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    path : Path.Bridge & U32 <- IO.try(Path.Bridge & U32,
      Path.start(url,List.replicate(U32,32n,42),Fixture.dialer_public(),port))
    serve_path(listener,path)

def listen(url: String) -> IO(Unit):
  do IO<Unit>:
    bound : Direct.QuicListener & U32 <- IO.try(Direct.QuicListener & U32,
      Direct.bind("127.0.0.1",0,List.replicate(U32,32n,42),Fixture.dialer_public(),Fixture.alpn()))
    answer(bound,url)

def exchange(path: Path.Bridge & U32) -> IO(Unit):
  (bridge,port) = path
  do IO<Unit>:
    response : Result<&1,&1,U32 & String,List<&2,U32>> <- Direct.exchange("127.0.0.1",port,List.replicate(U32,32n,73),
      Fixture.listener_public(),Fixture.alpn(),Fixture.payload(),1024)
    IO.try(Unit,Path.stop(bridge))
    echoed : List<&2,U32> <- IO.try(List<&2,U32>,IO.pure(Result<&1,&1,U32 & String,List<&2,U32>>,response))
    Fixture.assert_equal(Fixture.equal(echoed,Fixture.payload()))
    IO.print("PASS pinned QUIC stream exchanged over the Iroh relay")

def dial(url: String) -> IO(Unit):
  do IO<Unit>:
    path : Path.Bridge & U32 <- IO.try(Path.Bridge & U32,
      Path.start(url,List.replicate(U32,32n,73),Fixture.listener_public(),0))
    exchange(path)

def stream_exchange(opened: Direct.QuicConnection & Direct.QuicIoStream) -> IO(Unit):
  (conn,stream) = opened
  do IO<Unit>:
    written : Direct.QuicIoStream <- Stream.send(stream,Fixture.payload())
    outcome : Direct.QuicIoStream & List<&2,U32> <- Stream.read_all(32n,written,[])
    Stream.validate(outcome,Fixture.payload())
    Stream.drain(conn)

def verify_stream(conn: Direct.QuicConnection) -> IO(Unit):
  do IO<Unit>:
    opened : Direct.QuicConnection & Direct.QuicIoStream <-
      Stream.poll(Direct.QuicConnection,Direct.QuicIoStream,Stream.open_bidi,3000n,conn)
    stream_exchange(opened)

def verified_route(connected: Direct.QuicConnection & Maybe<&1,Path.Bridge>, relayed: Bool) -> IO(Unit):
  match connected relayed:
    case (conn,Some{bridge}) True{}:
      do IO<Unit>:
        verify_stream(conn)
        IO.try(Unit,Path.stop(bridge))
        IO.print("PASS QUIC fallback selected the relay after the direct deadline")
    case (conn,None{}) False{}:
      do IO<Unit>:
        verify_stream(conn)
        IO.print("PASS QUIC kept the direct path with no relay connection")
    case _ _:
      IO.die(Unit,1,"unexpected QUIC path selection")

def route(port: U32, url: String, direct_ms: U32)
    -> IO(Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Path.Bridge>>):
  Path.dial_with_fallback("127.0.0.1",port,direct_ms,url,6000,List.replicate(U32,32n,73),
    Fixture.listener_public(),Fixture.alpn())

def result_route(outcome: Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Path.Bridge>>, relayed: Bool)
    -> IO(Unit):
  match outcome:
    case Done{connected}:
      verified_route(connected,relayed)
    case Fail{(code,message)}:
      IO.die(Unit,code,message)

def check_deadline(waited: Bool) -> IO(Unit):
  match waited:
    case True{}:
      IO.pure(Unit,Unit{})
    case False{}:
      IO.die(Unit,1,"direct attempt ended before its handshake deadline")

def silent_path(bound: Socket & Result<&1,&1,U32 & String,U32>, url: String) -> IO(Unit):
  match bound:
    case (socket,Done{port}):
      do IO<Unit>:
        before : Nat <- IO.now()
        result : Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Path.Bridge>> <- route(port,url,250)
        after : Nat <- IO.now()
        Socket.close(socket)
        check_deadline(Nat.is_ge(Nat.sub(after,before),200n))
        result_route(result,True{})
    case (socket,Fail{(code,message)}):
      do IO<Unit>:
        Socket.close(socket)
        IO.die(Unit,code,message)

def expect_fallback(url: String) -> IO(Unit):
  do IO<Unit>:
    silent : Socket <- IO.try(Socket,UDP.bind("127.0.0.1",0))
    bound : Socket & Result<&1,&1,U32 & String,U32> <- Path.relay_loopback_port(silent)
    silent_path(bound,url)

def expect_direct(port: Maybe<&2,U32>) -> IO(Unit):
  match port:
    case Some{n}:
      do IO<Unit>:
        result : Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Path.Bridge>> <- route(n,"unused://relay",3000)
        result_route(result,False{})
    case None{}:
      IO.die(Unit,2,"expected the direct listener port")

def unreachable(result: Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Path.Bridge>>) -> IO(Unit):
  match result:
    case Fail{(_,"QUIC handshake timed out")}:
      IO.print("PASS failed relay handshake released the bridge")
    case _:
      IO.die(Unit,1,"expected the relay handshake to expire")

def silent_relay(port: Socket & Result<&1,&1,U32 & String,U32>, url: String) -> IO(Unit):
  match port:
    case (socket,Done{n}):
      do IO<Unit>:
        result : Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Path.Bridge>> <-
          Path.dial_with_fallback("127.0.0.1",n,120,url,200,List.replicate(U32,32n,73),
            Fixture.listener_public(),Fixture.alpn())
        Socket.close(socket)
        unreachable(result)
    case (socket,Fail{(code,message)}):
      do IO<Unit>:
        Socket.close(socket)
        IO.die(Unit,code,message)

def expect_unreachable(url: String) -> IO(Unit):
  do IO<Unit>:
    socket : Socket <- IO.try(Socket,UDP.bind("127.0.0.1",0))
    port : Socket & Result<&1,&1,U32 & String,U32> <- Path.relay_loopback_port(socket)
    silent_relay(port,url)

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{"listen",Con{url,Nil{}}}}:
      listen(url)
    case Con{_,Con{"dial",Con{url,Nil{}}}}:
      dial(url)
    case Con{_,Con{"dial-fallback",Con{url,Nil{}}}}:
      expect_fallback(url)
    case Con{_,Con{"listen-direct",Nil{}}}:
      Fixture.listen("127.0.0.1","",False{})
    case Con{_,Con{"dial-direct",Con{port,Nil{}}}}:
      expect_direct(U32.read(port))
    case Con{_,Con{"dial-unreachable",Con{url,Nil{}}}}:
      expect_unreachable(url)
    case _:
      IO.die(Unit,2,"usage: relay-quic-check listen|dial relay-url")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
