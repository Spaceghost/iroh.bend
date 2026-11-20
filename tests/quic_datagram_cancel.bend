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

def exchange(conn: Q.DatagramConnection) -> IO(Unit):
  Test.advance(~Q.DatagramConnection,~Test.Driver{Fixture.step,perform,Q.drop_quic_datagram},conn,0,1,Test.scenarios(),4000n)

def accepted(pair: Q.QuicDatagramListener & Q.DatagramConnection) -> IO(Unit):
  (listener,conn) = pair
  do IO<Unit>:
    exchange(conn)
    Q.close_shared_quic(listener)

def serve(bound: Q.QuicDatagramListener & U32) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    pair : Q.QuicDatagramListener & Q.DatagramConnection <- Fixture.server_accept(9000n,listener)
    accepted(pair)

def command(host: String, port: Maybe<&2,U32>) -> IO(Unit):
  match port:
    case Some{0}:
      do IO<Unit>:
        bound : Q.QuicDatagramListener & U32 <- IO.try(Q.QuicDatagramListener & U32,
          Q.bind_shared_quic(host,0,List.replicate(U32,32n,73),Fixture.public_key(False{}),Fixture.fixture_alpn()))
        serve(bound)
    case Some{port}:
      do IO<Unit>:
        conn : Q.DatagramConnection <- IO.try(Q.DatagramConnection,
          Q.connect(host,port,List.replicate(U32,32n,73),Fixture.public_key(False{}),Fixture.fixture_alpn(),5000n))
        exchange(conn)
    case None{}:
      IO.die(Unit,1,"expected a UDP port")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{host,Con{port,Nil{}}}}:
      command(host,U32.read(port))
    case _:
      IO.die(Unit,1,"expected an IP address and UDP port")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
