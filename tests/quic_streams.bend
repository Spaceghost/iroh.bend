import Base
import ../src/direct.bend as Direct
import ./direct.bend as Fixture

def continue_poll(-A: Type, -B: Type,
    outcome: A & Poll<&1,&1,Result<&1,&1,U32 & String,B>,Unit>, retry: A -> IO(A & B))
    -> IO(A & B):
  match outcome:
    case (owner,Ready{Done{data}}):
      IO.pure(A & B,(owner,data))
    case (_,Ready{Fail{(code,message)}}):
      IO.die(A & B,code,message)
    case (owner,Wait{_}):
      do IO<A & B>:
        IO.sleep(2)
        retry(owner)

def poll(~A: Type, ~B: Type, ~action: A -> IO(A & Poll<&1,&1,Result<&1,&1,U32 & String,B>,Unit>),
    fuel: Nat, owner: A) -> IO(A & B):
  match fuel:
    case 1n+left:
      do IO<A & B>:
        outcome : A & Poll<&1,&1,Result<&1,&1,U32 & String,B>,Unit> <- action(owner)
        continue_poll(A,B,outcome,next => poll(~A,~B,~action,left,next))
    case 0n:
      IO.die(A & B,1,"QUIC stream operation timed out")

def checked(-A: Type, outcome: A & Result<&1,&1,U32 & String,Unit>) -> IO(A):
  match outcome:
    case (owner,Done{_}):
      IO.pure(A,owner)
    case (_,Fail{(code,message)}):
      IO.die(A,code,message)

def open_bidi(conn: Direct.QuicConnection)
    -> IO(Direct.QuicConnection & Poll<&1,&1,Result<&1,&1,U32 & String,Direct.QuicIoStream>,Unit>):
  Direct.quic_open_stream(conn,0)

def open_uni(conn: Direct.QuicConnection)
    -> IO(Direct.QuicConnection & Poll<&1,&1,Result<&1,&1,U32 & String,Direct.QuicIoStream>,Unit>):
  Direct.quic_open_stream(conn,1)

def read_chunk(stream: Direct.QuicIoStream)
    -> IO(Direct.QuicIoStream & Poll<&1,&1,Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>,Unit>):
  Direct.quic_read(stream,4096)

def write(stream: Direct.QuicIoStream, bytes: List<&2,U32>) -> IO(Direct.QuicIoStream):
  do IO<Direct.QuicIoStream>:
    queued : Direct.QuicIoStream & Result<&1,&1,U32 & String,Unit> <- Direct.quic_queue_write(stream,bytes)
    ready : Direct.QuicIoStream <- checked(Direct.QuicIoStream,queued)
    flushed : Direct.QuicIoStream & Unit <- poll(Direct.QuicIoStream,Unit,Direct.quic_flush,4000n,ready)
    return Pair.fst(Direct.QuicIoStream,Unit,flushed)

def finish(stream: Direct.QuicIoStream) -> IO(Direct.QuicIoStream):
  do IO<Direct.QuicIoStream>:
    sent : Direct.QuicIoStream & Result<&1,&1,U32 & String,Unit> <- Direct.quic_finish(stream)
    checked(Direct.QuicIoStream,sent)

def send(stream: Direct.QuicIoStream, bytes: List<&2,U32>) -> IO(Direct.QuicIoStream):
  do IO<Direct.QuicIoStream>:
    sent : Direct.QuicIoStream <- write(stream,bytes)
    finish(sent)

def next_read(outcome: Direct.QuicIoStream & Maybe<&1,List<&2,U32>>, reversed: List<&2,U32>,
    step: Direct.QuicIoStream -> List<&2,U32> -> IO(Direct.QuicIoStream & List<&2,U32>))
    -> IO(Direct.QuicIoStream & List<&2,U32>):
  match outcome:
    case (stream,Some{bytes}):
      step(stream,List.append(&2,U32,List.reverse(&2,U32,bytes),reversed))
    case (stream,None{}):
      IO.pure(Direct.QuicIoStream & List<&2,U32>,(stream,List.reverse(&2,U32,reversed)))

def read_all(fuel: Nat, stream: Direct.QuicIoStream, reversed: List<&2,U32>)
    -> IO(Direct.QuicIoStream & List<&2,U32>):
  match fuel:
    case 1n+left:
      do IO<Direct.QuicIoStream & List<&2,U32>>:
        outcome : Direct.QuicIoStream & Maybe<&1,List<&2,U32>> <-
          poll(Direct.QuicIoStream,Maybe<&1,List<&2,U32>>,read_chunk,4000n,stream)
        next_read(outcome,reversed,next => bytes => read_all(left,next,bytes))
    case 0n:
      IO.die(Direct.QuicIoStream & List<&2,U32>,1,"too many test stream chunks")

def validate(outcome: Direct.QuicIoStream & List<&2,U32>, expected: List<&2,U32>) -> IO(Unit):
  (stream,data) = outcome
  do IO<Unit>:
    Direct.quic_drop_stream(stream)
    Fixture.assert_equal(Fixture.equal(data,expected))

def echo(outcome: Direct.QuicIoStream & List<&2,U32>, expected: List<&2,U32>) -> IO(Unit):
  (stream,+data) = outcome
  do IO<Unit>:
    Fixture.assert_equal(Fixture.equal(data,expected))
    finished : Direct.QuicIoStream <- send(stream,data)
    Direct.quic_drop_stream(finished)

def drain(conn: Direct.QuicConnection) -> IO(Unit):
  do IO<Unit>:
    drained : Direct.QuicConnection & Unit <- poll(Direct.QuicConnection,Unit,Direct.quic_shutdown,4000n,conn)
    Direct.quic_drop_connection(Pair.fst(Direct.QuicConnection,Unit,drained))

def large() -> List<&2,U32>:
  List.replicate(U32,131072n,42)

def server_reply(opened: Direct.QuicConnection & Direct.QuicIoStream) -> IO(Unit):
  (conn,sink) = opened
  do IO<Unit>:
    sent : Direct.QuicIoStream <- send(sink,[111,255,0])
    Direct.quic_drop_stream(sent)
    drain(conn)

def server_uni(incoming: Direct.QuicConnection & Direct.QuicIoStream) -> IO(Unit):
  (conn,source) = incoming
  do IO<Unit>:
    request : Direct.QuicIoStream & List<&2,U32> <- read_all(4096n,source,[])
    validate(request,[110,0,255])
    opened : Direct.QuicConnection & Direct.QuicIoStream <-
      poll(Direct.QuicConnection,Direct.QuicIoStream,open_uni,4000n,conn)
    server_reply(opened)

def server_second(second: Direct.QuicConnection & Direct.QuicIoStream, deferred: Direct.QuicIoStream) -> IO(Unit):
  (conn,stream) = second
  do IO<Unit>:
    pending : Chan(Direct.QuicIoStream & List<&2,U32>) <-
      IO.fork(Direct.QuicIoStream & List<&2,U32>,read_all(4096n,deferred,[]))
    b : Direct.QuicIoStream & List<&2,U32> <- read_all(4096n,stream,[])
    echo(b,large())
    a : Direct.QuicIoStream & List<&2,U32> <- IO.join(Direct.QuicIoStream & List<&2,U32>,pending)
    echo(a,[101,0,255,102])
    incoming : Direct.QuicConnection & Direct.QuicIoStream <-
      poll(Direct.QuicConnection,Direct.QuicIoStream,Direct.quic_accept_stream,4000n,conn)
    server_uni(incoming)

def server_first(first: Direct.QuicConnection & Direct.QuicIoStream) -> IO(Unit):
  (conn,stream) = first
  do IO<Unit>:
    second : Direct.QuicConnection & Direct.QuicIoStream <-
      poll(Direct.QuicConnection,Direct.QuicIoStream,Direct.quic_accept_stream,4000n,conn)
    server_second(second,stream)

def serve(conn: Direct.QuicConnection) -> IO(Unit):
  do IO<Unit>:
    first : Direct.QuicConnection & Direct.QuicIoStream <-
      poll(Direct.QuicConnection,Direct.QuicIoStream,Direct.quic_accept_stream,4000n,conn)
    server_first(first)

def server(bound: Direct.QuicListener & U32, prefix: String) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    IO.print(String.append(prefix,U32.show(port)))
    conn : Direct.QuicConnection <- IO.try(Direct.QuicConnection,Direct.quic_accept_connection(listener))
    serve(conn)

def listen(host: String, prefix: String) -> IO(Unit):
  do IO<Unit>:
    bound : Direct.QuicListener & U32 <- IO.try(Direct.QuicListener & U32,
      Direct.bind(host,0,List.replicate(U32,32n,42),Fixture.dialer_public(),Fixture.alpn()))
    server(bound,prefix)

def check_rebound(bound: Direct.QuicListener & U32) -> IO(Unit):
  (listener,_) = bound
  IO.try(Unit,Direct.close(listener))

def serve_both(accepted: Direct.QuicListener & Direct.QuicConnection, other: Direct.QuicConnection,
    host: String, port: U32) -> IO(Unit):
  (listener,conn) = accepted
  do IO<Unit>:
    IO.try(Unit,Direct.close(listener))
    task : Chan(Unit) <- IO.fork(Unit,serve(other))
    serve(conn)
    IO.join(Unit,task)
    rebound : Direct.QuicListener & U32 <- IO.try(Direct.QuicListener & U32,
      Direct.bind(host,port,List.replicate(U32,32n,42),Fixture.dialer_public(),Fixture.alpn()))
    check_rebound(rebound)

def accept_next(accepted: Direct.QuicListener & Direct.QuicConnection, host: String, port: U32) -> IO(Unit):
  (listener,conn) = accepted
  do IO<Unit>:
    next : Direct.QuicListener & Direct.QuicConnection <-
      poll(Direct.QuicListener,Direct.QuicConnection,Direct.quic_try_accept_connection,4000n,listener)
    serve_both(next,conn,host,port)

def listen_again(bound: Direct.QuicListener & U32, host: String, prefix: String) -> IO(Unit):
  (listener,+port) = bound
  do IO<Unit>:
    IO.print(String.append(prefix,U32.show(port)))
    first : Direct.QuicListener & Direct.QuicConnection <-
      poll(Direct.QuicListener,Direct.QuicConnection,Direct.quic_try_accept_connection,4000n,listener)
    accept_next(first,host,port)

def listen_many(+host: String, prefix: String) -> IO(Unit):
  do IO<Unit>:
    bound : Direct.QuicListener & U32 <- IO.try(Direct.QuicListener & U32,
      Direct.bind(host,0,List.replicate(U32,32n,42),Fixture.dialer_public(),Fixture.alpn()))
    listen_again(bound,host,prefix)

def client_receive(incoming: Direct.QuicConnection & Direct.QuicIoStream) -> IO(Unit):
  (conn,source) = incoming
  do IO<Unit>:
    response : Direct.QuicIoStream & List<&2,U32> <- read_all(4096n,source,[])
    validate(response,[111,255,0])
    drain(conn)

def client_uni(outgoing: Direct.QuicConnection & Direct.QuicIoStream) -> IO(Unit):
  (conn,sink) = outgoing
  do IO<Unit>:
    sent : Direct.QuicIoStream <- send(sink,[110,0,255])
    Direct.quic_drop_stream(sent)
    incoming : Direct.QuicConnection & Direct.QuicIoStream <-
      poll(Direct.QuicConnection,Direct.QuicIoStream,Direct.quic_accept_stream,4000n,conn)
    client_receive(incoming)

def client_second(second: Direct.QuicConnection & Direct.QuicIoStream, deferred: Direct.QuicIoStream) -> IO(Unit):
  (conn,stream) = second
  do IO<Unit>:
    outbound : Direct.QuicIoStream <- send(stream,large())
    b : Direct.QuicIoStream & List<&2,U32> <- read_all(4096n,outbound,[])
    validate(b,large())
    a_outbound : Direct.QuicIoStream <- send(deferred,[255,102])
    a : Direct.QuicIoStream & List<&2,U32> <- read_all(4096n,a_outbound,[])
    validate(a,[101,0,255,102])
    outgoing : Direct.QuicConnection & Direct.QuicIoStream <-
      poll(Direct.QuicConnection,Direct.QuicIoStream,open_uni,4000n,conn)
    client_uni(outgoing)

def client_first(first: Direct.QuicConnection & Direct.QuicIoStream) -> IO(Unit):
  (conn,stream) = first
  do IO<Unit>:
    deferred : Direct.QuicIoStream <- write(stream,[101,0])
    second : Direct.QuicConnection & Direct.QuicIoStream <-
      poll(Direct.QuicConnection,Direct.QuicIoStream,open_bidi,4000n,conn)
    client_second(second,deferred)

def dial(host: String, port: Maybe<&2,U32>, seed: U32) -> IO(Unit):
  match port:
    case Some{p}:
      do IO<Unit>:
        conn : Direct.QuicConnection <- IO.try(Direct.QuicConnection,
          Direct.quic_connect(host,p,List.replicate(U32,32n,seed),Fixture.listener_public(),Fixture.alpn()))
        opened : Direct.QuicConnection & Direct.QuicIoStream <-
          poll(Direct.QuicConnection,Direct.QuicIoStream,open_bidi,4000n,conn)
        client_first(opened)
    case None{}:
      IO.die(Unit,2,"expected a port")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{"listen",Nil{}}}:
      listen("127.0.0.1","127.0.0.1:")
    case Con{_,Con{"listen6",Nil{}}}:
      listen("::1","[::1]:")
    case Con{_,Con{"listen-many",Nil{}}}:
      listen_many("127.0.0.1","127.0.0.1:")
    case Con{_,Con{"listen-many6",Nil{}}}:
      listen_many("::1","[::1]:")
    case Con{_,Con{"dial-unpinned",Con{port,Nil{}}}}:
      dial("127.0.0.1",U32.read(port),74)
    case Con{_,Con{"dial",Con{port,Nil{}}}}:
      dial("127.0.0.1",U32.read(port),73)
    case Con{_,Con{"dial6",Con{port,Nil{}}}}:
      dial("::1",U32.read(port),73)
    case _:
      IO.die(Unit,2,"expected a QUIC test mode")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
