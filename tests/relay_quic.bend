import Base
import ../src/direct.bend as Direct
import ../src/relay_quic.bend as Path
import ./direct.bend as Fixture

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

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{"listen",Con{url,Nil{}}}}:
      listen(url)
    case Con{_,Con{"dial",Con{url,Nil{}}}}:
      dial(url)
    case _:
      IO.die(Unit,2,"usage: relay-quic-check listen|dial relay-url")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
