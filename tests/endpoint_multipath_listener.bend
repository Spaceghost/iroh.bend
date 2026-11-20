import Base
import ../src/endpoint_multipath.bend as Endpoint
import ../src/quic_multipath.bend as Quic
import ./quic_multipath_bend.bend as Fixture
import ./quic_multipath_listener.bend as Listener

def accept_result(pair: Endpoint.RelayedListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>>,
    wait: Endpoint.RelayedListener -> IO(Endpoint.RelayedListener & Quic.MultipathConnection))
    -> IO(Endpoint.RelayedListener & Quic.MultipathConnection):
  match pair:
    case (listener,Done{Some{conn}}):
      IO.pure(Endpoint.RelayedListener & Quic.MultipathConnection,(listener,conn))
    case (listener,Done{None{}}):
      do IO<Endpoint.RelayedListener & Quic.MultipathConnection>:
        IO.sleep(1)
        wait(listener)
    case (listener,Fail{(code,message)}):
      do IO<Endpoint.RelayedListener & Quic.MultipathConnection>:
        _ : Result<&1,&1,U32 & String,Unit> <- Endpoint.close_listener(listener)
        IO.die(Endpoint.RelayedListener & Quic.MultipathConnection,code,message)

def accept(fuel: Nat, listener: Endpoint.RelayedListener) -> IO(Endpoint.RelayedListener & Quic.MultipathConnection):
  match fuel:
    case 0n:
      do IO<Endpoint.RelayedListener & Quic.MultipathConnection>:
        _ : Result<&1,&1,U32 & String,Unit> <- Endpoint.close_listener(listener)
        IO.die(Endpoint.RelayedListener & Quic.MultipathConnection,1,"shared listener accept timed out")
    case 1n+left:
      do IO<Endpoint.RelayedListener & Quic.MultipathConnection>:
        pair : Endpoint.RelayedListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>> <-
          Endpoint.accept_listener(listener)
        accept_result(pair,next => accept(left,next))

def read_request(pair: Quic.MultipathConnection & Quic.MultipathRead, expected: List<&2,U32>,
    retry: Quic.MultipathConnection -> List<&2,U32> -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  match pair expected:
    case (conn,Quic.MultipathReadPending{}) remaining:
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        retry(conn,remaining)
    case (conn,Quic.MultipathReadBytes{[byte]}) Con{want,remaining}:
      Fixture.check_byte(conn,U32.is_eq(byte,want),next => _ => retry(next,remaining))
    case (conn,Quic.MultipathReadFin{}) Nil{}:
      IO.pure(Quic.MultipathConnection,conn)
    case (conn,_) _:
      Fixture.reject(Quic.MultipathConnection,conn,1,"unexpected multipath stream result")

def read_stream(fuel: Nat, conn: Quic.MultipathConnection, +stream: U32, expected: List<&2,U32>)
    -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      Fixture.reject(Quic.MultipathConnection,conn,1,"multipath stream read timed out")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        active : Quic.MultipathConnection <- Fixture.step(conn)
        input : Quic.MultipathConnection & Result<&1,&1,U32 & String,Quic.MultipathRead> <-
          Quic.read_multipath_stream(active,stream,1)
        read : Quic.MultipathConnection & Quic.MultipathRead <- Fixture.ok(Quic.MultipathRead,input)
        read_request(read,expected,next => bytes => read_stream(left,next,stream,bytes))

def queued(pair: Quic.MultipathConnection & U32, +label: U32) -> IO(Unit):
  match pair:
    case (conn,1):
      do IO<Unit>:
        confirmed : Quic.MultipathConnection <- Fixture.read_datagram(4000n,conn,[label,2,255])
        Quic.close_multipath(confirmed)
    case (conn,_):
      Fixture.reject(Unit,conn,1,"could not queue multipath stream reply")

def exchange_stream(opened: Quic.MultipathConnection & U32, +label: U32) -> IO(Unit):
  (conn,+stream) = opened
  do IO<Unit>:
    received : Quic.MultipathConnection <- read_stream(4000n,conn,stream,[label,1,255])
    reply : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <-
      Quic.write_multipath_stream(received,stream,[255,1,label],1)
    result : Quic.MultipathConnection & U32 <- Fixture.ok(U32,reply)
    queued(result,label)

def exchange(conn: Quic.MultipathConnection, +label: U32) -> IO(Unit):
  do IO<Unit>:
    received : Quic.MultipathConnection <- Fixture.read_datagram(4000n,conn,[label,0,255])
    sent : Quic.MultipathConnection <- Fixture.send_datagram(4000n,received,[255,0,label])
    opened : Quic.MultipathConnection & U32 <- Listener.incoming(4000n,sent,0)
    exchange_stream(opened,label)

def peer_label(a: Bool, b: Bool, c: Bool) -> U32:
  match a b c:
    case True{} _ _:
      73
    case _ True{} _:
      74
    case _ _ True{}:
      75
    case _ _ _:
      0

def identify(+key: List<&2,U32>) -> U32:
  peer_label(
    Fixture.same_bytes(key,[119,44,138,68,43,125,176,110,22,108,251,193,204,188,188,222,111,62,186,118,164,233,142,243,255,197,25,80,34,55,214,239]),
    Fixture.same_bytes(key,[53,60,138,127,238,202,56,178,196,83,110,11,210,88,111,219,24,208,112,229,14,5,159,29,67,248,191,239,185,122,124,225]),
    Fixture.same_bytes(key,[126,160,227,189,82,226,7,201,211,176,235,166,92,7,4,230,111,202,45,142,22,90,23,82,24,177,116,252,65,96,228,19]))

def serve_label(label: U32, conn: Quic.MultipathConnection) -> IO(U32):
  match label:
    case 0:
      Fixture.reject(U32,conn,1,"unexpected authenticated peer")
    case +label:
      do IO<U32>:
        exchange(conn,label)
        return U32.shln(1,U32.to_nat(U32.sub(label,73)))

def serve_peer(pair: Quic.MultipathConnection & List<&2,U32>) -> IO(U32):
  (conn,key) = pair
  serve_label(identify(key),conn)

def authenticate(pair: Quic.MultipathConnection & U32) -> IO(U32):
  match pair:
    case (conn,2):
      do IO<U32>:
        found : Quic.MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>> <- Quic.multipath_remote_id(conn)
        peer : Quic.MultipathConnection & List<&2,U32> <- Fixture.ok(List<&2,U32>,found)
        serve_peer(peer)
    case (conn,_):
      Fixture.reject(U32,conn,1,"multipath was not negotiated")

def serve(conn: Quic.MultipathConnection) -> IO(U32):
  do IO<U32>:
    step : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.step_multipath(conn)
    ready : Quic.MultipathConnection & U32 <- Fixture.ok(U32,step)
    authenticate(ready)

def verify(bits: U32) -> IO(Unit):
  match bits:
    case 7:
      IO.print("PASS Bend authenticated three peers through the same listener")
    case _:
      IO.die(Unit,1,"expected three distinct multipath peer identities")

def serve_all(pair: Endpoint.RelayedListener & Quic.MultipathConnection,
    first: Quic.MultipathConnection, second: Quic.MultipathConnection) -> IO(Unit):
  (listener,third) = pair
  do IO<Unit>:
    a : U32 <- serve(first)
    b : U32 <- serve(second)
    c : U32 <- serve(third)
    IO.try(Unit,Endpoint.close_listener(listener))
    verify(U32.or(a,U32.or(b,c)))

def third(pair: Endpoint.RelayedListener & Quic.MultipathConnection, first: Quic.MultipathConnection) -> IO(Unit):
  (listener,second) = pair
  do IO<Unit>:
    accepted : Endpoint.RelayedListener & Quic.MultipathConnection <- accept(12000n,listener)
    serve_all(accepted,first,second)

def second(pair: Endpoint.RelayedListener & Quic.MultipathConnection) -> IO(Unit):
  (listener,first) = pair
  do IO<Unit>:
    accepted : Endpoint.RelayedListener & Quic.MultipathConnection <- accept(12000n,listener)
    third(accepted,first)

def first(pair: Endpoint.RelayedListener & U32) -> IO(Unit):
  (listener,port) = pair
  do IO<Unit>:
    IO.print(String.append("direct and relay identity listener ready ",U32.show(port)))
    accepted : Endpoint.RelayedListener & Quic.MultipathConnection <- accept(12000n,listener)
    second(accepted)

def listen(url: String) -> IO(Unit):
  do IO<Unit>:
    listener : Endpoint.RelayedListener & U32 <- IO.try(Endpoint.RelayedListener & U32,
      Endpoint.bind_direct_relay_identity(0,url,List.replicate(U32,32n,42),[Fixture.text_alpn()],0))
    first(listener)

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_, "listen-direct-relay", url]:
      listen(url)
    case _:
      IO.die(Unit,2,"expected listen-direct-relay and the relay URL")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
