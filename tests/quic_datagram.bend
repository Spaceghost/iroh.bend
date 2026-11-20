import Base
import ../src/quic_datagram.bend as Quic

type Mode is Type:
  PacketAck{}
  ApplicationEcho{}
  SharedConnection{}
  WrongKey{}

def public_key(wrong: Bool) -> List<&2,U32>:
  match wrong:
    case False{}:
      [25,127,107,35,225,108,133,50,198,171,200,56,250,205,94,167,
       137,190,12,118,178,146,3,52,3,155,250,139,61,54,141,97]
    case True{}:
      [119,44,138,68,43,125,176,110,22,108,251,193,204,188,188,222,
       111,62,186,118,164,233,142,243,255,197,25,80,34,55,214,239]

def check_progress(outcome: Quic.DatagramConnection & Result<&1,&1,U32 & String,U32>)
    -> IO(Quic.DatagramConnection & U32):
  match outcome:
    case (conn,Done{value}):
      IO.pure(Quic.DatagramConnection & U32,(conn,value))
    case (conn,Fail{(code,message)}):
      do IO<Quic.DatagramConnection & U32>:
        Quic.drop_quic_datagram(conn)
        IO.die(Quic.DatagramConnection & U32,code,message)

def next_connection(outcome: Quic.DatagramConnection & U32) -> IO(Quic.DatagramConnection):
  (next,_) = outcome
  IO.pure(Quic.DatagramConnection,next)

def step(conn: Quic.DatagramConnection) -> IO(Quic.DatagramConnection):
  do IO<Quic.DatagramConnection>:
    result : Quic.DatagramConnection & Result<&1,&1,U32 & String,U32> <- Quic.step_quic_datagram(conn)
    outcome : Quic.DatagramConnection & U32 <- check_progress(result)
    next_connection(outcome)

def check_ack(outcome: Quic.DatagramConnection & U32, resume: Quic.DatagramConnection -> IO(Unit)) -> IO(Unit):
  match outcome:
    case (next,0):
      do IO<Unit>:
        IO.sleep(2)
        resume(next)
    case (done,_):
      do IO<Unit>:
        Quic.drop_quic_datagram(done)
        IO.print("PASS authenticated upstream Iroh acknowledged an RFC 9221 QUIC datagram packet")

def wait_ack(fuel: Nat, conn: Quic.DatagramConnection) -> IO(Unit):
  match fuel:
    case 0n:
      do IO<Unit>:
        Quic.drop_quic_datagram(conn)
        IO.die(Unit,1,"Iroh did not acknowledge the QUIC datagram packet")
    case 1n+left:
      do IO<Unit>:
        ready : Quic.DatagramConnection <- step(conn)
        result : Quic.DatagramConnection & Result<&1,&1,U32 & String,U32> <- Quic.quic_datagram_acks(ready)
        outcome : Quic.DatagramConnection & U32 <- check_progress(result)
        check_ack(outcome,next => wait_ack(left,next))

def check_write(outcome: Quic.DatagramConnection & U32,
    resume: Quic.DatagramConnection -> IO(Quic.DatagramConnection)) -> IO(Quic.DatagramConnection):
  match outcome:
    case (waiting,0):
      do IO<Quic.DatagramConnection>:
        IO.sleep(2)
        next : Quic.DatagramConnection <- step(waiting)
        resume(next)
    case (conn,_):
      IO.pure(Quic.DatagramConnection,conn)

def send_datagram(fuel: Nat, conn: Quic.DatagramConnection, +payload: List<&2,U32>)
    -> IO(Quic.DatagramConnection):
  match fuel:
    case 0n:
      do IO<Quic.DatagramConnection>:
        Quic.drop_quic_datagram(conn)
        IO.die(Quic.DatagramConnection,1,"QUIC datagram write stayed blocked")
    case 1n+left:
      do IO<Quic.DatagramConnection>:
        result : Quic.DatagramConnection & Result<&1,&1,U32 & String,U32> <-
          Quic.write_quic_datagram(conn,payload)
        outcome : Quic.DatagramConnection & U32 <- check_progress(result)
        check_write(outcome,next => send_datagram(left,next,payload))

def same_bytes(expected: List<&2,U32>, actual: List<&2,U32>) -> Bool:
  match expected actual:
    case Nil{} Nil{}:
      True{}
    case Con{first,rest} Con{value,tail}:
      U32.is_eq(first,value) && same_bytes(rest,tail)
    case _ _:
      False{}

def check_reply(conn: Quic.DatagramConnection, identical: Bool) -> IO(Quic.DatagramConnection):
  match identical:
    case True{}:
      IO.pure(Quic.DatagramConnection,conn)
    case False{}:
      do IO<Quic.DatagramConnection>:
        Quic.drop_quic_datagram(conn)
        IO.die(Quic.DatagramConnection,1,"upstream Iroh application datagram reply differed")

def received_reply(outcome: Quic.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>,
    expected: List<&2,U32>, retry: Quic.DatagramConnection -> IO(Quic.DatagramConnection))
    -> IO(Quic.DatagramConnection):
  match outcome:
    case (conn,Done{Some{data}}):
      check_reply(conn,same_bytes(expected,data))
    case (conn,Done{None{}}):
      do IO<Quic.DatagramConnection>:
        IO.sleep(2)
        retry(conn)
    case (conn,Fail{(code,message)}):
      do IO<Quic.DatagramConnection>:
        Quic.drop_quic_datagram(conn)
        IO.die(Quic.DatagramConnection,code,message)

def receive_reply(fuel: Nat, conn: Quic.DatagramConnection, +expected: List<&2,U32>)
    -> IO(Quic.DatagramConnection):
  match fuel:
    case 0n:
      do IO<Quic.DatagramConnection>:
        Quic.drop_quic_datagram(conn)
        IO.die(Quic.DatagramConnection,1,"upstream Iroh application datagram timed out")
    case 1n+left:
      do IO<Quic.DatagramConnection>:
        ready : Quic.DatagramConnection <- step(conn)
        outcome : Quic.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>> <-
          Quic.read_quic_datagram(ready)
        received_reply(outcome,expected,waiting => receive_reply(left,waiting,expected))

type StreamAction is Data:
  OpenStream{direction: U32}
  AcceptStream{direction: U32}
  QueueStream{id: U32, bytes: List<&2,U32>, finish: U32}
  FlushStream{id: U32}

def stream_action(conn: Quic.DatagramConnection, action: StreamAction)
    -> IO(Quic.DatagramConnection & Result<&1,&1,U32 & String,U32>):
  match action:
    case OpenStream{direction}:
      Quic.open_quic_stream(conn,direction)
    case AcceptStream{direction}:
      Quic.accept_quic_stream(conn,direction)
    case QueueStream{id,bytes,finish}:
      Quic.queue_quic_stream(conn,id,bytes,finish)
    case FlushStream{id}:
      Quic.flush_quic_stream(conn,id)

def poll_stream_value(outcome: Quic.DatagramConnection & U32,
    retry: Quic.DatagramConnection -> IO(Quic.DatagramConnection & U32))
    -> IO(Quic.DatagramConnection & U32):
  match outcome:
    case (conn,0):
      do IO<Quic.DatagramConnection & U32>:
        IO.sleep(1)
        retry(conn)
    case value:
      IO.pure(Quic.DatagramConnection & U32,value)

def poll_stream(fuel: Nat, conn: Quic.DatagramConnection, +action: StreamAction)
    -> IO(Quic.DatagramConnection & U32):
  match fuel:
    case 0n:
      do IO<Quic.DatagramConnection & U32>:
        Quic.drop_quic_datagram(conn)
        IO.die(Quic.DatagramConnection & U32,1,"shared QUIC stream operation timed out")
    case 1n+left:
      do IO<Quic.DatagramConnection & U32>:
        ready : Quic.DatagramConnection <- step(conn)
        result : Quic.DatagramConnection & Result<&1,&1,U32 & String,U32> <- stream_action(ready,action)
        outcome : Quic.DatagramConnection & U32 <- check_progress(result)
        poll_stream_value(outcome,next => poll_stream(left,next,action))

def stream_submit(conn: Quic.DatagramConnection, action: StreamAction) -> IO(Quic.DatagramConnection):
  do IO<Quic.DatagramConnection>:
    outcome : Quic.DatagramConnection & U32 <- poll_stream(2500n,conn,action)
    next_connection(outcome)

def valid_prefix(equal: Bool, remaining: Maybe<&1,List<&2,U32>>) -> Maybe<&1,List<&2,U32>>:
  match equal:
    case True{}:
      remaining
    case False{}:
      None{}

def stream_prefix(actual: List<&2,U32>, expected: List<&2,U32>) -> Maybe<&1,List<&2,U32>>:
  match actual expected:
    case Nil{} tail:
      Some{tail}
    case Con{byte,rest} Con{value,tail}:
      valid_prefix(U32.is_eq(byte,value),stream_prefix(rest,tail))
    case _ _:
      None{}

def incomplete_stream(conn: Quic.DatagramConnection, message: String) -> IO(Quic.DatagramConnection):
  do IO<Quic.DatagramConnection>:
    Quic.drop_quic_datagram(conn)
    IO.die(Quic.DatagramConnection,1,message)

def consume_prefix(conn: Quic.DatagramConnection, remaining: Maybe<&1,List<&2,U32>>,
    next: Quic.DatagramConnection -> List<&2,U32> -> IO(Quic.DatagramConnection))
    -> IO(Quic.DatagramConnection):
  match remaining:
    case Some{tail}:
      next(conn,tail)
    case None{}:
      incomplete_stream(conn,"upstream Iroh stream sent unexpected bytes")

def consume_stream(outcome: Quic.DatagramConnection & Result<&1,&1,U32 & String,Quic.QuicStreamRead>,
    expected: List<&2,U32>, next: Quic.DatagramConnection -> List<&2,U32> -> IO(Quic.DatagramConnection))
    -> IO(Quic.DatagramConnection):
  match outcome expected:
    case (conn,Done{Quic.QuicStreamBytes{actual}}) tail:
      consume_prefix(conn,stream_prefix(actual,tail),next)
    case (conn,Done{Quic.QuicStreamFin{}}) Nil{}:
      IO.pure(Quic.DatagramConnection,conn)
    case (conn,Done{Quic.QuicStreamFin{}}) _:
      incomplete_stream(conn,"upstream Iroh stream ended before the expected bytes")
    case (conn,Done{Quic.QuicStreamPending{}}) tail:
      do IO<Quic.DatagramConnection>:
        IO.sleep(1)
        next(conn,tail)
    case (conn,Fail{(code,message)}) _:
      do IO<Quic.DatagramConnection>:
        Quic.drop_quic_datagram(conn)
        IO.die(Quic.DatagramConnection,code,message)

def receive_stream(fuel: Nat, conn: Quic.DatagramConnection, +id: U32, expected: List<&2,U32>)
    -> IO(Quic.DatagramConnection):
  match fuel:
    case 0n:
      incomplete_stream(conn,"upstream Iroh stream read timed out")
    case 1n+left:
      do IO<Quic.DatagramConnection>:
        ready : Quic.DatagramConnection <- step(conn)
        outcome : Quic.DatagramConnection & Result<&1,&1,U32 & String,Quic.QuicStreamRead> <-
          Quic.read_quic_stream(ready,id,4096)
        consume_stream(outcome,expected,next => tail => receive_stream(left,next,id,tail))

def released(outcome: Quic.DatagramConnection & Result<&1,&1,U32 & String,Unit>) -> IO(Quic.DatagramConnection):
  match outcome:
    case (conn,Done{_}):
      IO.pure(Quic.DatagramConnection,conn)
    case (conn,Fail{(code,message)}):
      do IO<Quic.DatagramConnection>:
        Quic.drop_quic_datagram(conn)
        IO.die(Quic.DatagramConnection,code,message)

def release_stream(conn: Quic.DatagramConnection, id: U32) -> IO(Quic.DatagramConnection):
  do IO<Quic.DatagramConnection>:
    outcome : Quic.DatagramConnection & Result<&1,&1,U32 & String,Unit> <- Quic.drop_quic_stream(conn,id)
    released(outcome)

def finish_shared(incoming: Quic.DatagramConnection & U32, +bidi_id: U32) -> IO(Unit):
  (reading,+incoming_id) = incoming
  do IO<Unit>:
    read : Quic.DatagramConnection <- receive_stream(2500n,reading,incoming_id,[7,0,255])
    bidi_only : Quic.DatagramConnection <- release_stream(read,incoming_id)
    bidi_flushed : Quic.DatagramConnection <- stream_submit(bidi_only,FlushStream{bidi_id})
    queued_tail : Quic.DatagramConnection <- stream_submit(bidi_flushed,QueueStream{bidi_id,[0,255],0})
    tail_sent : Quic.DatagramConnection <- stream_submit(queued_tail,FlushStream{bidi_id})
    queued_fin : Quic.DatagramConnection <- stream_submit(tail_sent,QueueStream{bidi_id,[],1})
    fin_sent : Quic.DatagramConnection <- stream_submit(queued_fin,FlushStream{bidi_id})
    bidi_read : Quic.DatagramConnection <- receive_stream(2500n,fin_sent,bidi_id,List.replicate(U32,70000n,18))
    complete : Quic.DatagramConnection <- release_stream(bidi_read,bidi_id)
    Quic.drop_quic_datagram(complete)
    IO.print("PASS binary, empty, and burst datagrams shared one Iroh connection with bidi and uni streams")

def start_shared(outgoing: Quic.DatagramConnection & U32, +bidi_id: U32) -> IO(Unit):
  (both,+uni_id) = outgoing
  do IO<Unit>:
    queued : Quic.DatagramConnection <- stream_submit(both,QueueStream{bidi_id,List.replicate(U32,16384n,17),0})
    first : Quic.DatagramConnection & Result<&1,&1,U32 & String,U32> <- Quic.flush_quic_stream(queued,bidi_id)
    partial : Quic.DatagramConnection & U32 <- check_progress(first)
    partial_conn : Quic.DatagramConnection <- next_connection(partial)
    uni_queued : Quic.DatagramConnection <- stream_submit(partial_conn,QueueStream{uni_id,[12,0,255],1})
    uni_flushed : Quic.DatagramConnection <- stream_submit(uni_queued,FlushStream{uni_id})
    sending : Quic.DatagramConnection <- release_stream(uni_flushed,uni_id)
    datagram : Quic.DatagramConnection <- send_datagram(1500n,sending,[2])
    reply : Quic.DatagramConnection <- receive_reply(1500n,datagram,[3])
    incoming : Quic.DatagramConnection & U32 <- poll_stream(2500n,reply,AcceptStream{1})
    finish_shared(incoming,bidi_id)

def shared_exchange(bidi: Quic.DatagramConnection & U32) -> IO(Unit):
  (conn,bidi_id) = bidi
  do IO<Unit>:
    outgoing : Quic.DatagramConnection & U32 <- poll_stream(2500n,conn,OpenStream{1})
    start_shared(outgoing,bidi_id)

def receive_burst(count: Nat, conn: Quic.DatagramConnection) -> IO(Quic.DatagramConnection):
  match count:
    case 0n:
      IO.pure(Quic.DatagramConnection,conn)
    case 1n+left:
      do IO<Quic.DatagramConnection>:
        next : Quic.DatagramConnection <- receive_reply(1500n,conn,[14,255])
        receive_burst(left,next)

def after_burst(conn: Quic.DatagramConnection, shared: Bool) -> IO(Unit):
  match shared:
    case True{}:
      do IO<Unit>:
        bidi : Quic.DatagramConnection & U32 <- poll_stream(2500n,conn,OpenStream{0})
        shared_exchange(bidi)
    case False{}:
      do IO<Unit>:
        Quic.drop_quic_datagram(conn)
        IO.print("PASS binary, empty, and burst datagrams exchanged with the upstream Iroh application")

def exchange_result(conn: Quic.DatagramConnection, echo: Bool, shared: Bool) -> IO(Unit):
  match echo:
    case True{}:
      do IO<Unit>:
        received : Quic.DatagramConnection <- receive_reply(1500n,conn,[255,0,17,128,1])
        sent : Quic.DatagramConnection <- send_datagram(1500n,received,[])
        empty : Quic.DatagramConnection <- receive_reply(1500n,sent,[])
        burst : Quic.DatagramConnection <- send_datagram(1500n,empty,[1])
        burst_done : Quic.DatagramConnection <- receive_burst(24n,burst)
        after_burst(burst_done,shared)
    case False{}:
      wait_ack(1500n,conn)

def exchange(conn: Quic.DatagramConnection, echo: Bool, shared: Bool) -> IO(Unit):
  do IO<Unit>:
    sent : Quic.DatagramConnection <- send_datagram(1500n,conn,[0,98,101,110,100,255])
    exchange_result(sent,echo,shared)

def check_size(outcome: Quic.DatagramConnection & Result<&1,&1,U32 & String,U32>, echo: Bool, shared: Bool) -> IO(Unit):
  match outcome:
    case (conn,Fail{(90,_)}):
      exchange(conn,echo,shared)
    case (conn,_):
      do IO<Unit>:
        Quic.drop_quic_datagram(conn)
        IO.die(Unit,1,"an oversized QUIC datagram did not return EMSGSIZE")

def no_unsolicited_datagram(outcome: Quic.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>,
    echo: Bool, shared: Bool)
    -> IO(Unit):
  match outcome:
    case (conn,Done{None{}}):
      do IO<Unit>:
        result : Quic.DatagramConnection & Result<&1,&1,U32 & String,U32> <-
          Quic.write_quic_datagram(conn,List.replicate(U32,1501n,0))
        check_size(result,echo,shared)
    case (conn,_):
      do IO<Unit>:
        Quic.drop_quic_datagram(conn)
        IO.die(Unit,1,"expected an empty QUIC datagram inbox")

def check_empty(conn: Quic.DatagramConnection, echo: Bool, shared: Bool) -> IO(Unit):
  do IO<Unit>:
    outcome : Quic.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>> <-
      Quic.read_quic_datagram(conn)
    no_unsolicited_datagram(outcome,echo,shared)

def check_dial(mode: Mode, result: Result<&1,&1,U32 & String,Quic.DatagramConnection>) -> IO(Unit):
  match mode result:
    case PacketAck{} Done{conn}:
      check_empty(conn,False{},False{})
    case ApplicationEcho{} Done{conn}:
      check_empty(conn,True{},False{})
    case SharedConnection{} Done{conn}:
      check_empty(conn,True{},True{})
    case WrongKey{} Fail{(13,_)}:
      IO.print("PASS Bend TLS rejected the wrong pin for upstream Iroh")
    case _ Fail{(code,message)}:
      IO.die(Unit,code,message)
    case WrongKey{} Done{conn}:
      do IO<Unit>:
        Quic.drop_quic_datagram(conn)
        IO.die(Unit,1,"QUIC accepted a mismatched endpoint pin")

def dial(host: String, port: Maybe<&2,U32>, mode: Mode, wrong: Bool) -> IO(Unit):
  match port:
    case Some{number}:
      do IO<Unit>:
        result : Result<&1,&1,U32 & String,Quic.DatagramConnection> <- Quic.connect(
          host,number,List.replicate(U32,32n,73),public_key(wrong),
          [105,114,111,104,45,98,101,110,100,47,99,111,109,112,97,116,47,49],5000n)
        check_dial(mode,result)
    case None{}:
      IO.die(Unit,2,"expected a UDP port")

def usage() -> IO(Unit):
  IO.die(Unit,2,"usage: quic-datagram listen|listen6 | HOST PORT valid|echo|shared|wrong-key")

def choose(host: String, port: Maybe<&2,U32>, valid: Bool, echo: Bool, shared: Bool, rejected: Bool) -> IO(Unit):
  match valid echo shared rejected:
    case True{} _ _ _:
      dial(host,port,PacketAck{},False{})
    case _ True{} _ _:
      dial(host,port,ApplicationEcho{},False{})
    case _ _ True{} _:
      dial(host,port,SharedConnection{},False{})
    case _ _ _ True{}:
      dial(host,port,WrongKey{},True{})
    case _ _ _ _:
      usage()

def server_accept_result(
    outcome: Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.DatagramConnection>>,
    next: Quic.QuicDatagramListener -> IO(Quic.QuicDatagramListener & Quic.DatagramConnection))
    -> IO(Quic.QuicDatagramListener & Quic.DatagramConnection):
  match outcome:
    case (listener,Done{Some{conn}}):
      IO.pure(Quic.QuicDatagramListener & Quic.DatagramConnection,(listener,conn))
    case (listener,Done{None{}}):
      do IO<Quic.QuicDatagramListener & Quic.DatagramConnection>:
        IO.sleep(1)
        next(listener)
    case (listener,Fail{(code,message)}):
      do IO<Quic.QuicDatagramListener & Quic.DatagramConnection>:
        Quic.close_shared_quic(listener)
        IO.die(Quic.QuicDatagramListener & Quic.DatagramConnection,code,message)

def server_accept(fuel: Nat, listener: Quic.QuicDatagramListener)
    -> IO(Quic.QuicDatagramListener & Quic.DatagramConnection):
  match fuel:
    case 0n:
      do IO<Quic.QuicDatagramListener & Quic.DatagramConnection>:
        Quic.close_shared_quic(listener)
        IO.die(Quic.QuicDatagramListener & Quic.DatagramConnection,1,"Bend QUIC listener timed out")
    case 1n+left:
      do IO<Quic.QuicDatagramListener & Quic.DatagramConnection>:
        accepted : Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.DatagramConnection>> <-
          Quic.try_accept_shared_quic(listener)
        server_accept_result(accepted,next => server_accept(left,next))

def server_uni_request(incoming: Quic.DatagramConnection & U32, label: U32) -> IO(Quic.DatagramConnection):
  (conn,+stream) = incoming
  do IO<Quic.DatagramConnection>:
    read : Quic.DatagramConnection <- receive_stream(2500n,conn,stream,[label,1,255])
    release_stream(read,stream)

def server_stream_reply(outgoing: Quic.DatagramConnection & U32, payload: List<&2,U32>) -> IO(Quic.DatagramConnection):
  (conn,+stream) = outgoing
  do IO<Quic.DatagramConnection>:
    queued : Quic.DatagramConnection <- stream_submit(conn,QueueStream{stream,payload,1})
    sent : Quic.DatagramConnection <- stream_submit(queued,FlushStream{stream})
    release_stream(sent,stream)

def server_bidi_exchange(incoming: Quic.DatagramConnection & U32, +label: U32) -> IO(Quic.DatagramConnection):
  (conn,+stream) = incoming
  do IO<Quic.DatagramConnection>:
    read : Quic.DatagramConnection <- receive_stream(2500n,conn,stream,[label,2,255])
    server_stream_reply((read,stream),[label,255,2])

def server_exchange(conn: Quic.DatagramConnection, +label: U32) -> IO(Unit):
  do IO<Unit>:
    datagram : Quic.DatagramConnection <- receive_reply(5000n,conn,[label,0,255])
    echoed : Quic.DatagramConnection <- send_datagram(1500n,datagram,[label,255,0])
    uni : Quic.DatagramConnection & U32 <- poll_stream(2500n,echoed,AcceptStream{1})
    read : Quic.DatagramConnection <- server_uni_request(uni,label)
    outgoing : Quic.DatagramConnection & U32 <- poll_stream(2500n,read,OpenStream{1})
    unis_done : Quic.DatagramConnection <- server_stream_reply(outgoing,[label,255,1])
    bidi : Quic.DatagramConnection & U32 <- poll_stream(2500n,unis_done,AcceptStream{0})
    replied : Quic.DatagramConnection <- server_bidi_exchange(bidi,label)
    confirmed : Quic.DatagramConnection <- receive_reply(5000n,replied,[label,3])
    Quic.drop_quic_datagram(confirmed)

def serve_two(second: Quic.QuicDatagramListener & Quic.DatagramConnection, first: Quic.DatagramConnection) -> IO(Unit):
  (listener,conn) = second
  do IO<Unit>:
    Quic.close_shared_quic(listener)
    server_exchange(first,41)
    server_exchange(conn,42)
    IO.print("PASS Iroh clients exchanged datagrams and streams through one Bend listener")

def accept_second(first: Quic.QuicDatagramListener & Quic.DatagramConnection) -> IO(Unit):
  (listener,conn) = first
  do IO<Unit>:
    second : Quic.QuicDatagramListener & Quic.DatagramConnection <- server_accept(15000n,listener)
    serve_two(second,conn)

def serve(bound: Quic.QuicDatagramListener & U32, prefix: String) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    IO.print(String.append(prefix,U32.show(port)))
    first : Quic.QuicDatagramListener & Quic.DatagramConnection <- server_accept(15000n,listener)
    accept_second(first)

def listen(host: String, prefix: String) -> IO(Unit):
  do IO<Unit>:
    bound : Quic.QuicDatagramListener & U32 <- IO.try(Quic.QuicDatagramListener & U32,
      Quic.bind_shared_quic(host,0,List.replicate(U32,32n,42),public_key(True{}),
        [105,114,111,104,45,98,101,110,100,47,99,111,109,112,97,116,47,49]))
    serve(bound,prefix)

def choose_listener(v4: Bool, v6: Bool) -> IO(Unit):
  match v4 v6:
    case True{} _:
      listen("127.0.0.1","127.0.0.1:")
    case _ True{}:
      listen("::1","[::1]:")
    case _ _:
      usage()

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{+mode,Nil{}}}:
      choose_listener(String.eq(mode,"listen"),String.eq(mode,"listen6"))
    case Con{_,Con{host,Con{port,Con{+mode,Nil{}}}}}:
      choose(host,U32.read(port),String.eq(mode,"valid"),String.eq(mode,"echo"),String.eq(mode,"shared"),String.eq(mode,"wrong-key"))
    case _:
      usage()

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
