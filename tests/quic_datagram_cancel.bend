import Base
import ./quic_stream_cancel.bend as Test
import ../src/quic_nat.bend as Wire
import ../src/quic_datagram.bend as Q
import ./quic_datagram.bend as Fixture

def read_state(value: Q.QuicStreamRead) -> Test.State:
  match value:
    case Q.QuicStreamPending{}:
      Test.Pending{}
    case Q.QuicStreamFin{}:
      Test.Fin{}
    case Q.QuicStreamBytes{bytes}:
      Test.byte_value(bytes)

def handle(value: U32) -> Test.State:
  match value:
    case 0:
      Test.Pending{}
    case id:
      Test.Handle{id}

def perform(conn: Q.DatagramConnection, id: U32, action: Test.Action) -> Test.Reply(Q.DatagramConnection):
  match action:
    case Test.Open{dir}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,U32> <- Q.open_quic_stream(conn,dir)
        Test.answer(Q.DatagramConnection,U32,raw,handle)
    case Test.Accept{dir}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,U32> <- Q.accept_quic_stream(conn,dir)
        Test.answer(Q.DatagramConnection,U32,raw,handle)
    case Test.Write{byte,fin}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,U32> <- Q.queue_quic_stream(conn,id,[byte],fin)
        Test.answer(Q.DatagramConnection,U32,raw,Test.queued)
    case Test.FinalWrite{count}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,U32> <- Q.queue_quic_stream(conn,id,List.replicate(U32,count,32),1)
        Test.answer(Q.DatagramConnection,U32,raw,Test.queued)
    case Test.FinAck{}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,U32> <- Q.quic_stream_fin_acked(conn,id)
        Test.answer(Q.DatagramConnection,U32,raw,value => Test.Flag{value})
    case Test.ResetAck{}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,U32> <- Q.quic_stream_reset_acked(conn,id)
        Test.answer(Q.DatagramConnection,U32,raw,value => Test.Flag{value})
    case Test.Gate{message}:
      Test.gate(Q.DatagramConnection,conn,message)
    case Test.PendingNotice{message}:
      do IO<Q.DatagramConnection & Test.State>:
        IO.print(message)
        return (conn,Test.Complete{})
    case Test.Flush{}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,U32> <- Q.flush_quic_stream(conn,id)
        Test.answer(Q.DatagramConnection,U32,raw,Test.queued)
    case Test.Read{}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,Q.QuicStreamRead> <- Q.read_quic_stream(conn,id,1)
        Test.answer(Q.DatagramConnection,Q.QuicStreamRead,raw,read_state)
    case Test.SendDatagram{byte}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,U32> <- Q.write_quic_datagram(conn,[byte])
        Test.answer(Q.DatagramConnection,U32,raw,Test.queued)
    case Test.ReadDatagram{}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>> <- Q.read_quic_datagram(conn)
        Test.answer(Q.DatagramConnection,Maybe<&1,List<&2,U32>>,raw,Test.packet)
    case Test.Reset{why}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,Unit> <- Q.reset_quic_stream(conn,id,why)
        Test.answer(Q.DatagramConnection,Unit,raw,Test.complete)
    case Test.Stop{why}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,Unit> <- Q.stop_quic_stream(conn,id,why)
        Test.answer(Q.DatagramConnection,Unit,raw,Test.complete)
    case Test.PeerReset{}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&2,Wire.VarInt>> <- Q.quic_stream_reset_code(conn,id)
        Test.answer(Q.DatagramConnection,Maybe<&2,Wire.VarInt>,raw,Test.code)
    case Test.PeerStop{}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,Maybe<&2,Wire.VarInt>> <- Q.quic_stream_stop_code(conn,id)
        Test.answer(Q.DatagramConnection,Maybe<&2,Wire.VarInt>,raw,Test.code)
    case Test.Drop{}:
      do IO<Q.DatagramConnection & Test.State>:
        raw : Q.DatagramConnection & Result<&1,&1,U32 & String,Unit> <- Q.drop_quic_stream(conn,id)
        Test.answer(Q.DatagramConnection,Unit,raw,Test.complete)

def exchange(conn: Q.DatagramConnection, checks: List<&2,Test.Check>) -> IO(Unit):
  Test.advance(~Q.DatagramConnection,~Test.Driver{Fixture.step,perform,Q.drop_quic_datagram},conn,0,1,checks,4000n)

def accepted(pair: Q.QuicDatagramListener & Q.DatagramConnection, checks: List<&2,Test.Check>) -> IO(Unit):
  (listener,conn) = pair
  do IO<Unit>:
    exchange(conn,checks)
    Q.close_shared_quic(listener)

def serve(bound: Q.QuicDatagramListener & U32, checks: List<&2,Test.Check>) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    pair : Q.QuicDatagramListener & Q.DatagramConnection <- Fixture.server_accept(9000n,listener)
    accepted(pair,checks)

def command(host: String, port: Maybe<&2,U32>, checks: List<&2,Test.Check>) -> IO(Unit):
  match port:
    case Some{0}:
      do IO<Unit>:
        bound : Q.QuicDatagramListener & U32 <- IO.try(Q.QuicDatagramListener & U32,
          Q.bind_shared_quic(host,0,List.replicate(U32,32n,73),Fixture.public_key(False{}),Fixture.fixture_alpn()))
        serve(bound,checks)
    case Some{port}:
      do IO<Unit>:
        conn : Q.DatagramConnection <- IO.try(Q.DatagramConnection,
          Q.connect(host,port,List.replicate(U32,32n,73),Fixture.public_key(False{}),Fixture.fixture_alpn(),5000n))
        exchange(conn,checks)
    case None{}:
      IO.die(Unit,1,"expected a UDP port")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{host,Con{port,Nil{}}}}:
      command(host,U32.read(port),Test.scenarios())
    case Con{_,Con{host,Con{port,Con{"finish",Nil{}}}}}:
      command(host,U32.read(port),Test.finish_checks())
    case Con{_,Con{host,Con{port,Con{"reset-ack",Nil{}}}}}:
      command(host,U32.read(port),Test.reset_ack_checks(False{}))
    case Con{_,Con{host,Con{port,Con{"reset-ack-return",Nil{}}}}}:
      command(host,U32.read(port),Test.reset_ack_checks(True{}))
    case _:
      IO.die(Unit,1,"expected an IP address and UDP port")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
