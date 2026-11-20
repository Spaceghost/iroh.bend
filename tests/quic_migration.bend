import Base
import ../src/quic_datagram.bend as Quic
import ./quic_datagram.bend as Fixture

def start_move(fuel: Nat, conn: Quic.DatagramConnection, +host: String)
    -> IO(Quic.DatagramConnection & U32):
  match fuel:
    case 0n:
      do IO<Quic.DatagramConnection & U32>:
        Quic.drop_quic_datagram(conn)
        IO.die(Quic.DatagramConnection & U32,1,"could not start QUIC path validation")
    case 1n+left:
      do IO<Quic.DatagramConnection & U32>:
        stepped : Quic.DatagramConnection <- Fixture.step(conn)
        result : Quic.DatagramConnection & Result<&1,&1,U32 & String,U32> <-
          Quic.start_quic_migration(stepped,host,0)
        progress : Quic.DatagramConnection & U32 <- Fixture.check_progress(result)
        Fixture.poll_stream_value(progress,next => start_move(left,next,host))

def poll_move(outcome: Quic.DatagramConnection & U32,
    retry: Quic.DatagramConnection -> IO(Quic.DatagramConnection & U32))
    -> IO(Quic.DatagramConnection & U32):
  match outcome:
    case (conn,1):
      do IO<Quic.DatagramConnection & U32>:
        IO.sleep(1)
        retry(conn)
    case finished:
      IO.pure(Quic.DatagramConnection & U32,finished)

def await_move(fuel: Nat, conn: Quic.DatagramConnection) -> IO(Quic.DatagramConnection & U32):
  match fuel:
    case 0n:
      do IO<Quic.DatagramConnection & U32>:
        Quic.drop_quic_datagram(conn)
        IO.die(Quic.DatagramConnection & U32,1,"QUIC path validation timed out")
    case 1n+left:
      do IO<Quic.DatagramConnection & U32>:
        stepped : Quic.DatagramConnection <- Fixture.step(conn)
        result : Quic.DatagramConnection & Result<&1,&1,U32 & String,U32> <- Quic.quic_migration_status(stepped)
        progress : Quic.DatagramConnection & U32 <- Fixture.check_progress(result)
        poll_move(progress,next => await_move(left,next))

def check_move_status(conn: Quic.DatagramConnection, code: U32, same: Bool) -> IO(Quic.DatagramConnection):
  match same:
    case True{}:
      IO.pure(Quic.DatagramConnection,conn)
    case False{}:
      Fixture.incomplete_stream(conn,String.append("unexpected QUIC migration status ",U32.show(code)))

def check_move(outcome: Quic.DatagramConnection & U32, expected: U32) -> IO(Quic.DatagramConnection):
  (conn,+code) = outcome
  check_move_status(conn,code,U32.is_eq(code,expected))

def migrate(bound: Quic.DatagramConnection & U32, +stream: U32, +expected: U32) -> IO(Unit):
  (conn,port) = bound
  do IO<Unit>:
    IO.print(String.append("CANDIDATE ",U32.show(port)))
    outcome : Quic.DatagramConnection & U32 <- await_move(12000n,conn)
    ready : Quic.DatagramConnection <- check_move(outcome,expected)
    IO.print(String.append("VALIDATION ",U32.show(expected)))
    sent : Quic.DatagramConnection <- Fixture.send_datagram(2000n,ready,[12,0,255])
    queued : Quic.DatagramConnection <- Fixture.stream_submit(sent,Fixture.QueueStream{stream,[22,0,255],1})
    flushed : Quic.DatagramConnection <- Fixture.stream_submit(queued,Fixture.FlushStream{stream})
    reply : Quic.DatagramConnection <- Fixture.receive_reply(2000n,flushed,[13,0,255])
    read : Quic.DatagramConnection <- Fixture.receive_stream(2000n,reply,stream,[21,0,255,23,0,255])
    complete : Quic.DatagramConnection <- Fixture.send_datagram(2000n,read,[14,0,255])
    Quic.drop_quic_datagram(complete)
    IO.print("PASS Bend kept the original QUIC connection and stream")

def initial(opened: Quic.DatagramConnection & U32, host: String, expected: U32) -> IO(Unit):
  (conn,+stream) = opened
  do IO<Unit>:
    sent : Quic.DatagramConnection <- Fixture.send_datagram(2000n,conn,[10,0,255])
    queued : Quic.DatagramConnection <- Fixture.stream_submit(sent,Fixture.QueueStream{stream,[20,0,255],0})
    flushed : Quic.DatagramConnection <- Fixture.stream_submit(queued,Fixture.FlushStream{stream})
    reply : Quic.DatagramConnection <- Fixture.receive_reply(2000n,flushed,[11,0,255])
    bound : Quic.DatagramConnection & U32 <- start_move(2500n,reply,host)
    migrate(bound,stream,expected)

def connect(+host: String, port: U32, expected: U32) -> IO(Unit):
  do IO<Unit>:
    conn : Quic.DatagramConnection <- IO.try(Quic.DatagramConnection,
      Quic.connect(host,port,List.replicate(U32,32n,73),Fixture.public_key(False{}),Fixture.fixture_alpn(),5000n))
    stream : Quic.DatagramConnection & U32 <- Fixture.poll_stream(2500n,conn,Fixture.OpenStream{0})
    initial(stream,host,expected)

def parse(host: String, port: Maybe<&2,U32>, status: Maybe<&2,U32>) -> IO(Unit):
  match port status:
    case Some{number} Some{expected}:
      connect(host,number,expected)
    case _ _:
      IO.die(Unit,2,"expected a port and migration status")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{host,Con{port,Con{status,Nil{}}}}}:
      parse(host,U32.read(port),U32.read(status))
    case _:
      IO.die(Unit,2,"expected a host, port, and migration status")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
