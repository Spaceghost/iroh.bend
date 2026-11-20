import Base
import ../src/quic_multipath.bend as Q
import ../src/quic_nat.bend as Wire
import ../src/quic_close.bend as Close
import ./quic_multipath_bend.bend as Peer
import ./quic_multipath_session.bend as Session
import ./quic_connection_close.bend as CloseTest
import ./quic_idle_timeout.bend as Idle
import ./quic_stream_cancel.bend as Gate

def quiet(conn: Q.MultipathConnection) -> IO(Unit):
  do IO<Unit>:
    sent : Q.MultipathConnection <- Peer.send_datagram(1500n,conn,[31,0,255])
    echoed : Q.MultipathConnection <- Peer.read_datagram(1500n,sent,[32,0,255])
    expired : Q.MultipathConnection <- Idle.wait(~Q.MultipathConnection,
      ~CloseTest.Operations{Q.close_multipath_connection,Q.multipath_close_reason,Q.step_multipath},echoed,8000n)
    reason : Q.MultipathConnection & Close.ReadResult() <- Q.multipath_close_reason(expired)
    done : Q.MultipathConnection <- Idle.timed_out(Q.MultipathConnection,reason)
    Q.close_multipath(done)
    IO.print("PASS resumed without early data and reported TimedOut")

def early_receipt(result: (Q.MultipathConnection & Q.MultipathEarlyStream) & Gate.State) -> IO(Unit):
  match result:
    case ((conn,stream),Gate.Complete{}):
      Session.wait_resume(4000n,conn,1,True{},ready => status => Session.stream_authenticated(ready,stream,status,0))
    case ((conn,_),_):
      Peer.reject(Unit,conn,1,"Iroh did not acknowledge the early stream and datagram")

def wait_early_receipt(conn: Q.MultipathConnection, stream: Q.MultipathEarlyStream) -> IO(Unit):
  do IO<Unit>:
    received : (Q.MultipathConnection & Q.MultipathEarlyStream) & Gate.State <-
      Gate.gate(Q.MultipathConnection & Q.MultipathEarlyStream,(conn,stream),"EARLY sent")
    early_receipt(received)

def send_early(result: Q.MultipathConnection & (Q.MultipathEarlyStream & Result<&1,&1,U32 & String,U32>)) -> IO(Unit):
  match result:
    case (conn,(stream,Done{1})):
      do IO<Unit>:
        sent : Q.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Q.write_multipath_early_datagram(conn,[4,0,255])
        Session.await_queue(sent,ready => wait_early_receipt(ready,stream))
    case (conn,(_,Done{_})):
      Peer.reject(Unit,conn,1,"could not queue the early stream")
    case (conn,(_,Fail{(code,message)})):
      Peer.reject(Unit,conn,code,message)

def write_early(opened: Q.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,Q.MultipathEarlyStream>>) -> IO(Unit):
  match opened:
    case (conn,Done{Some{stream}}):
      do IO<Unit>:
        sent : Q.MultipathConnection & (Q.MultipathEarlyStream & Result<&1,&1,U32 & String,U32>) <-
          Q.write_multipath_early_stream(conn,stream,[7,0,255],1)
        send_early(sent)
    case (conn,Done{None{}}):
      Peer.reject(Unit,conn,1,"could not open the early stream")
    case (conn,Fail{(code,message)}):
      Peer.reject(Unit,conn,code,message)

def finish_client(conn: Q.MultipathConnection, mode: String) -> IO(Unit):
  match mode:
    case "quiet":
      Session.wait_resume(4000n,conn,1,False{},ready => _ => quiet(ready))
    case "reject":
      Session.probe_early(conn,9,True{},False{})
    case _:
      do IO<Unit>:
        opened : Q.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,Q.MultipathEarlyStream>> <-
          Q.open_multipath_early_stream(conn,0)
        write_early(opened)

def resume(host: String, port: U32, ticket: Q.MultipathSession, +mode: String, idle_ms: Wire.VarInt) -> IO(Unit):
  do IO<Unit>:
    conn : Q.MultipathConnection <- IO.try(Q.MultipathConnection,
      Q.start_multipath_resume_with_idle_timeout(host,port,List.replicate(U32,32n,73),Peer.fixture_key(0),Peer.text_alpn(),ticket,
        Bool.to_u32(Bool.not(String.eq(mode,"quiet"))),idle_ms))
    finish_client(conn,mode)

def dial(+host: String, warm: U32, port: U32, mode: String, idle_ms: Wire.VarInt) -> IO(Unit):
  do IO<Unit>:
    conn : Q.MultipathConnection <- IO.try(Q.MultipathConnection,
      Q.connect_multipath_bytes(host,warm,List.replicate(U32,32n,73),Peer.fixture_key(0),Peer.text_alpn(),5000n))
    Session.wait_ticket(4000n,conn,ticket => resume(host,port,ticket,mode,idle_ms))

def pair(a: Maybe<&2,U32>, b: Maybe<&2,U32>, run: U32 -> U32 -> IO(Unit)) -> IO(Unit):
  match a b:
    case Some{x} Some{y}:
      run(x,y)
    case _ _:
      IO.die(Unit,2,"expected unsigned decimal numbers")

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_, "client",host,warm,port,mode,hi,lo]:
      pair(U32.read(hi),U32.read(lo),h => l => pair(U32.read(warm),U32.read(port),w => p => dial(host,w,p,mode,Wire.Var{h,l})))
    case _:
      IO.die(Unit,2,"expected client resumption arguments")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
