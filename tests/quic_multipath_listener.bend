import Base
import ../src/quic_multipath.bend as Quic
import ./quic_multipath_bend.bend as Fixture

def accepted_result(pair: Quic.MultipathListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>>,
    retry: Quic.MultipathListener -> IO(Quic.MultipathListener & Quic.MultipathConnection))
    -> IO(Quic.MultipathListener & Quic.MultipathConnection):
  match pair:
    case (listener,Done{Some{conn}}):
      IO.pure(Quic.MultipathListener & Quic.MultipathConnection,(listener,conn))
    case (listener,Done{None{}}):
      do IO<Quic.MultipathListener & Quic.MultipathConnection>:
        IO.sleep(1)
        retry(listener)
    case (listener,Fail{(code,message)}):
      do IO<Quic.MultipathListener & Quic.MultipathConnection>:
        Quic.close_multipath_listener(listener)
        IO.die(Quic.MultipathListener & Quic.MultipathConnection,code,message)

def accept(fuel: Nat, listener: Quic.MultipathListener) -> IO(Quic.MultipathListener & Quic.MultipathConnection):
  match fuel:
    case 0n:
      do IO<Quic.MultipathListener & Quic.MultipathConnection>:
        Quic.close_multipath_listener(listener)
        IO.die(Quic.MultipathListener & Quic.MultipathConnection,1,"multipath accept timed out")
    case 1n+left:
      do IO<Quic.MultipathListener & Quic.MultipathConnection>:
        result : Quic.MultipathListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>> <-
          Quic.accept_multipath(listener)
        accepted_result(result,next => accept(left,next))

def incoming(fuel: Nat, conn: Quic.MultipathConnection, +dir: U32) -> IO(Quic.MultipathConnection & U32):
  match fuel:
    case 0n:
      Fixture.reject(Quic.MultipathConnection & U32,conn,1,"incoming multipath stream timed out")
    case 1n+left:
      do IO<Quic.MultipathConnection & U32>:
        active : Quic.MultipathConnection <- Fixture.step(conn)
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <-
          Quic.accept_multipath_stream(active,dir)
        progress : Quic.MultipathConnection & Maybe<&1,U32> <- Fixture.ok(Maybe<&1,U32>,result)
        Fixture.probe_result(progress,next => incoming(left,next,dir))

def read_uni(opened: Quic.MultipathConnection & U32, byte: U32) -> IO(Quic.MultipathConnection):
  (conn,+stream) = opened
  do IO<Quic.MultipathConnection>:
    read : Quic.MultipathConnection <- Fixture.receive(4000n,conn,stream,byte,False{})
    Fixture.release(read,stream)

def receive_uni(conn: Quic.MultipathConnection, byte: U32) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    opened : Quic.MultipathConnection & U32 <- incoming(4000n,conn,1)
    read_uni(opened,byte)

def echo(opened: Quic.MultipathConnection & U32, path: U32, +byte: U32) -> IO(Quic.MultipathConnection):
  (conn,+stream) = opened
  do IO<Quic.MultipathConnection>:
    read : Quic.MultipathConnection <- Fixture.receive(4000n,conn,stream,byte,False{})
    sent : Quic.MultipathConnection & U32 <- Fixture.send((read,stream),path,byte)
    return Fixture.stepped(sent)

def echo_pair(conn: Quic.MultipathConnection, first: U32, second: U32, path: U32)
    -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    a : Quic.MultipathConnection & U32 <- incoming(4000n,conn,0)
    echoed_a : Quic.MultipathConnection <- echo(a,0,first)
    b : Quic.MultipathConnection & U32 <- incoming(4000n,echoed_a,0)
    echo(b,path,second)

def datagram_echo(conn: Quic.MultipathConnection) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    binary : Quic.MultipathConnection <- Fixture.read_datagram(4000n,conn,[0,128,255])
    sent : Quic.MultipathConnection <- Fixture.send_datagram(4000n,binary,[255,128,0])
    empty : Quic.MultipathConnection <- Fixture.read_datagram(4000n,sent,[])
    Fixture.send_datagram(4000n,empty,[])

def exchange(conn: Quic.MultipathConnection, uni: U32, first: U32, second: U32) -> IO(Unit):
  do IO<Unit>:
    datagrams : Quic.MultipathConnection <- datagram_echo(conn)
    primed : Quic.MultipathConnection <- receive_uni(datagrams,uni)
    echoed : Quic.MultipathConnection <- echo_pair(primed,first,second,0)
    confirmed : Quic.MultipathConnection <- receive_uni(echoed,77)
    Quic.close_multipath(confirmed)

def wait_path(fuel: Nat, conn: Quic.MultipathConnection) -> IO(Quic.MultipathConnection & U32):
  match fuel:
    case 0n:
      Fixture.reject(Quic.MultipathConnection & U32,conn,1,"peer did not open a second path")
    case 1n+left:
      do IO<Quic.MultipathConnection & U32>:
        active : Quic.MultipathConnection <- Fixture.step(conn)
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <-
          Quic.next_multipath_path(active,0)
        paths : Quic.MultipathConnection & Maybe<&1,U32> <- Fixture.ok(Maybe<&1,U32>,result)
        Fixture.probe_result(paths,next => wait_path(left,next))

def waited(result: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>,
    resume: Quic.MultipathConnection -> IO(Unit)) -> IO(Unit):
  match result:
    case (conn,Done{_}):
      do IO<Unit>:
        IO.sleep(1)
        resume(conn)
    case (conn,Fail{(104,_)}):
      do IO<Unit>:
        Quic.close_multipath(conn)
        IO.print("PASS Bend listener accepted and used the dialer's second path")
    case (conn,Fail{(code,message)}):
      Fixture.reject(Unit,conn,code,message)

def wait_close(fuel: Nat, conn: Quic.MultipathConnection) -> IO(Unit):
  match fuel:
    case 0n:
      Fixture.reject(Unit,conn,1,"multipath peer did not close")
    case 1n+left:
      do IO<Unit>:
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.step_multipath(conn)
        waited(result,next => wait_close(left,next))

def echo_affine(candidate: Quic.MultipathConnection & U32) -> IO(Unit):
  (conn,path) = candidate
  do IO<Unit>:
    datagrams : Quic.MultipathConnection <- datagram_echo(conn)
    echoed : Quic.MultipathConnection <- echo_pair(datagrams,11,22,path)
    wait_close(5000n,echoed)

def serve_affinity(first: Quic.MultipathListener & Quic.MultipathConnection) -> IO(Unit):
  (listener,conn) = first
  do IO<Unit>:
    Quic.close_multipath_listener(listener)
    candidate : Quic.MultipathConnection & U32 <- wait_path(5000n,conn)
    echo_affine(candidate)

def serve_two(second: Quic.MultipathListener & Quic.MultipathConnection, first: Quic.MultipathConnection) -> IO(Unit):
  (listener,conn) = second
  do IO<Unit>:
    Quic.close_multipath_listener(listener)
    exchange(first,55,11,22)
    exchange(conn,66,33,44)
    IO.print("PASS Bend served both connections after closing the multipath listener")

def serve_two_connections(first: Quic.MultipathListener & Quic.MultipathConnection) -> IO(Unit):
  (listener,conn) = first
  do IO<Unit>:
    second : Quic.MultipathListener & Quic.MultipathConnection <- accept(16000n,listener)
    serve_two(second,conn)

def serve(first: Quic.MultipathListener & Quic.MultipathConnection, mode: U32) -> IO(Unit):
  match mode:
    case 0:
      serve_two_connections(first)
    case _:
      serve_affinity(first)

def announce(bound: Quic.MultipathListener & U32, mode: U32) -> IO(Unit):
  (listener,local_port) = bound
  do IO<Unit>:
    IO.print(U32.show(local_port))
    first : Quic.MultipathListener & Quic.MultipathConnection <- accept(16000n,listener)
    serve(first,mode)

def fixture_peer() -> List<&2,U32>:
  [119,44,138,68,43,125,176,110,22,108,251,193,204,188,188,222,
   111,62,186,118,164,233,142,243,255,197,25,80,34,55,214,239]

def listen_text(host: String, mode: U32) -> IO(Unit):
  do IO<Unit>:
    bound : Quic.MultipathListener & U32 <- IO.try(Quic.MultipathListener & U32,
      Quic.bind_multipath(host,0,List.replicate(U32,32n,42),fixture_peer(),"iroh-bend/compat/1"))
    announce(bound,mode)

def listen_binary(host: String) -> IO(Unit):
  do IO<Unit>:
    bound : Quic.MultipathListener & U32 <- IO.try(Quic.MultipathListener & U32,
      Quic.bind_multipath_bytes(host,0,List.replicate(U32,32n,42),fixture_peer(),Fixture.binary_alpn()))
    announce(bound,0)

def parse(host: String, mode: Maybe<&2,U32>) -> IO(Unit):
  match mode:
    case Some{2}:
      listen_binary(host)
    case Some{number}:
      listen_text(host,number)
    case None{}:
      IO.die(Unit,2,"expected a listener mode")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{host,Con{port,Nil{}}}}:
      parse(host,U32.read(port))
    case _:
      IO.die(Unit,2,"expected a host and listener mode")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
