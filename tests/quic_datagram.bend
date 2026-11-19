import Base
import ../src/quic_datagram.bend as Quic

type Mode is Type:
  PacketAck{}
  ApplicationEcho{}
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

def receive_burst(count: Nat, conn: Quic.DatagramConnection) -> IO(Unit):
  match count:
    case 0n:
      do IO<Unit>:
        Quic.drop_quic_datagram(conn)
        IO.print("PASS exchanged binary, empty, and burst QUIC datagrams with the upstream Iroh application")
    case 1n+left:
      do IO<Unit>:
        next : Quic.DatagramConnection <- receive_reply(1500n,conn,[14,255])
        receive_burst(left,next)

def exchange_result(conn: Quic.DatagramConnection, echo: Bool) -> IO(Unit):
  match echo:
    case True{}:
      do IO<Unit>:
        received : Quic.DatagramConnection <- receive_reply(1500n,conn,[255,0,17,128,1])
        sent : Quic.DatagramConnection <- send_datagram(1500n,received,[])
        empty : Quic.DatagramConnection <- receive_reply(1500n,sent,[])
        burst : Quic.DatagramConnection <- send_datagram(1500n,empty,[1])
        receive_burst(24n,burst)
    case False{}:
      wait_ack(1500n,conn)

def exchange(conn: Quic.DatagramConnection, echo: Bool) -> IO(Unit):
  do IO<Unit>:
    sent : Quic.DatagramConnection <- send_datagram(1500n,conn,[0,98,101,110,100,255])
    exchange_result(sent,echo)

def check_size(outcome: Quic.DatagramConnection & Result<&1,&1,U32 & String,U32>, echo: Bool) -> IO(Unit):
  match outcome:
    case (conn,Fail{(90,_)}):
      exchange(conn,echo)
    case (conn,_):
      do IO<Unit>:
        Quic.drop_quic_datagram(conn)
        IO.die(Unit,1,"an oversized QUIC datagram did not return EMSGSIZE")

def no_unsolicited_datagram(outcome: Quic.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>,
    echo: Bool)
    -> IO(Unit):
  match outcome:
    case (conn,Done{None{}}):
      do IO<Unit>:
        result : Quic.DatagramConnection & Result<&1,&1,U32 & String,U32> <-
          Quic.write_quic_datagram(conn,List.replicate(U32,1501n,0))
        check_size(result,echo)
    case (conn,_):
      do IO<Unit>:
        Quic.drop_quic_datagram(conn)
        IO.die(Unit,1,"expected an empty QUIC datagram inbox")

def check_empty(conn: Quic.DatagramConnection, echo: Bool) -> IO(Unit):
  do IO<Unit>:
    outcome : Quic.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>> <-
      Quic.read_quic_datagram(conn)
    no_unsolicited_datagram(outcome,echo)

def check_dial(mode: Mode, result: Result<&1,&1,U32 & String,Quic.DatagramConnection>) -> IO(Unit):
  match mode result:
    case PacketAck{} Done{conn}:
      check_empty(conn,False{})
    case ApplicationEcho{} Done{conn}:
      check_empty(conn,True{})
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
  IO.die(Unit,2,"usage: quic-datagram HOST PORT valid|echo|wrong-key")

def choose(host: String, port: Maybe<&2,U32>, valid: Bool, echo: Bool, rejected: Bool) -> IO(Unit):
  match valid echo rejected:
    case True{} _ _:
      dial(host,port,PacketAck{},False{})
    case _ True{} _:
      dial(host,port,ApplicationEcho{},False{})
    case _ _ True{}:
      dial(host,port,WrongKey{},True{})
    case _ _ _:
      usage()

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{host,Con{port,Con{+mode,Nil{}}}}}:
      choose(host,U32.read(port),String.eq(mode,"valid"),String.eq(mode,"echo"),String.eq(mode,"wrong-key"))
    case _:
      usage()

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
