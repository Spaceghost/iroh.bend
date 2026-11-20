import Base
import ./quic_stream_cancel.bend as Test
import ./quic_connection_close.bend as CloseTest
import ../src/quic_nat.bend as Wire
import ../src/quic_multipath.bend as Q
import ./quic_multipath_bend.bend as Fixture
import ./quic_multipath_listener.bend as Listener

def read_state(value: Q.MultipathRead) -> Test.State:
  match value:
    case Q.MultipathReadPending{}:
      Test.Pending{}
    case Q.MultipathReadFin{}:
      Test.Fin{}
    case Q.MultipathReadBytes{bytes}:
      Test.byte_value(bytes)

def perform(conn: Q.MultipathConnection, id: U32, action: Test.Action) -> Test.Reply(Q.MultipathConnection):
  match action:
    case Test.Open{dir}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <- Q.open_multipath_stream(conn,dir)
        Test.answer(Q.MultipathConnection,Maybe<&1,U32>,raw,Test.handle)
    case Test.Accept{dir}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <- Q.accept_multipath_stream(conn,dir)
        Test.answer(Q.MultipathConnection,Maybe<&1,U32>,raw,Test.handle)
    case Test.Write{byte,fin}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Q.write_multipath_stream(conn,id,[byte],fin)
        Test.answer(Q.MultipathConnection,U32,raw,Test.queued)
    case Test.FinalWrite{count}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Q.write_multipath_stream(conn,id,List.replicate(U32,count,32),1)
        Test.answer(Q.MultipathConnection,U32,raw,Test.queued)
    case Test.FinAck{}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Q.multipath_stream_fin_acked(conn,id)
        Test.answer(Q.MultipathConnection,U32,raw,value => Test.Flag{value})
    case Test.ResetAck{}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Q.multipath_stream_reset_acked(conn,id)
        Test.answer(Q.MultipathConnection,U32,raw,value => Test.Flag{value})
    case Test.Gate{message}:
      Test.gate(Q.MultipathConnection,conn,message)
    case Test.PendingNotice{message}:
      do IO<Q.MultipathConnection & Test.State>:
        IO.print(message)
        return (conn,Test.Complete{})
    case Test.Flush{}:
      IO.pure(Q.MultipathConnection & Test.State,(conn,Test.Complete{}))
    case Test.Read{}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,Q.MultipathRead> <- Q.read_multipath_stream(conn,id,1)
        Test.answer(Q.MultipathConnection,Q.MultipathRead,raw,read_state)
    case Test.SendDatagram{byte}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Q.write_multipath_datagram(conn,[byte])
        Test.answer(Q.MultipathConnection,U32,raw,Test.queued)
    case Test.ReadDatagram{}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>> <- Q.read_multipath_datagram(conn)
        Test.answer(Q.MultipathConnection,Maybe<&1,List<&2,U32>>,raw,Test.packet)
    case Test.Reset{why}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,Unit> <- Q.reset_multipath_stream(conn,id,why)
        Test.answer(Q.MultipathConnection,Unit,raw,Test.complete)
    case Test.Stop{why}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,Unit> <- Q.stop_multipath_stream(conn,id,why)
        Test.answer(Q.MultipathConnection,Unit,raw,Test.complete)
    case Test.PeerReset{}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&2,Wire.VarInt>> <- Q.multipath_stream_reset_code(conn,id)
        Test.answer(Q.MultipathConnection,Maybe<&2,Wire.VarInt>,raw,Test.code)
    case Test.PeerStop{}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&2,Wire.VarInt>> <- Q.multipath_stream_stop_code(conn,id)
        Test.answer(Q.MultipathConnection,Maybe<&2,Wire.VarInt>,raw,Test.code)
    case Test.Drop{}:
      do IO<Q.MultipathConnection & Test.State>:
        raw : Q.MultipathConnection & Result<&1,&1,U32 & String,Unit> <- Q.drop_multipath_stream(conn,id)
        Test.answer(Q.MultipathConnection,Unit,raw,Test.complete)

type Suite is Data:
  StreamCases{checks: List<&2,Test.Check>}
  CloseCase{send: Bool, id: U32}

def exchange(conn: Q.MultipathConnection, suite: Suite) -> IO(Unit):
  match suite:
    case StreamCases{checks}:
      Test.advance(~Q.MultipathConnection,~Test.Driver{Fixture.step,perform,Q.close_multipath},conn,0,1,checks,4000n)
    case CloseCase{send,id}:
      CloseTest.exchange(~Q.MultipathConnection,~CloseTest.Operations{Q.close_multipath_connection,Q.multipath_close_reason,Q.step_multipath},
        ~Test.Driver{Fixture.step,perform,Q.close_multipath},conn,send,id)

def accepted(pair: Q.MultipathListener & Q.MultipathConnection, suite: Suite) -> IO(Unit):
  (listener,conn) = pair
  do IO<Unit>:
    exchange(conn,suite)
    Q.close_multipath_listener(listener)

def serve(bound: Q.MultipathListener & U32, suite: Suite) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    pair : Q.MultipathListener & Q.MultipathConnection <- Listener.accept(9000n,listener)
    accepted(pair,suite)

def command(host: String, port: Maybe<&2,U32>, suite: Suite) -> IO(Unit):
  match port:
    case Some{0}:
      do IO<Unit>:
        bound : Q.MultipathListener & U32 <- IO.try(Q.MultipathListener & U32,
          Q.bind_multipath_bytes(host,0,List.replicate(U32,32n,73),Fixture.fixture_key(0),Fixture.text_alpn()))
        serve(bound,suite)
    case Some{port}:
      do IO<Unit>:
        conn : Q.MultipathConnection <- IO.try(Q.MultipathConnection,
          Q.connect_multipath_bytes(host,port,List.replicate(U32,32n,73),Fixture.fixture_key(0),Fixture.text_alpn(),5000n))
        exchange(conn,suite)
    case None{}:
      IO.die(Unit,1,"expected a UDP port")

def close_case(host: String, port: String, send: Bool, id: Maybe<&2,U32>) -> IO(Unit):
  match id:
    case Some{value}:
      command(host,U32.read(port),CloseCase{send,value})
    case None{}:
      IO.die(Unit,1,"expected a close example number")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{host,Con{port,Nil{}}}}:
      command(host,U32.read(port),StreamCases{Test.scenarios()})
    case Con{_,Con{host,Con{port,Con{"finish",Nil{}}}}}:
      command(host,U32.read(port),StreamCases{Test.finish_checks()})
    case Con{_,Con{host,Con{port,Con{"reset-ack",Nil{}}}}}:
      command(host,U32.read(port),StreamCases{Test.reset_ack_checks(False{})})
    case Con{_,Con{host,Con{port,Con{"reset-ack-return",Nil{}}}}}:
      command(host,U32.read(port),StreamCases{Test.reset_ack_checks(True{})})
    case Con{_,Con{host,Con{port,Con{"send",Con{id,Nil{}}}}}}:
      close_case(host,port,True{},U32.read(id))
    case Con{_,Con{host,Con{port,Con{"receive",Con{id,Nil{}}}}}}:
      close_case(host,port,False{},U32.read(id))
    case _:
      IO.die(Unit,1,"expected an IP address and UDP port")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
