import Base
import ./quic_idle_listeners.bend as IdleTest
import ../src/quic_nat.bend as Wire
import ../src/quic_datagram.bend as Q
import ./quic_datagram.bend as Fixture
import ../src/endpoint.bend as Endpoint

def bind(host: String, idle_ms: Wire.VarInt) -> IO(Result<&1,&1,U32 & String,Q.QuicDatagramListener & U32>):
  Endpoint.bind_with_idle_timeout(Endpoint.IpAddress{host,0},
    Endpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.public_key(False{}),Fixture.fixture_alpn()},idle_ms)

def limits() -> IO(Unit):
  IdleTest.limits(~Q.QuicDatagramListener,~Q.DatagramConnection,
    ~(ms => bind("127.0.0.1",ms)),
    ~(port => ms => Q.start_quic_datagram_with_idle_timeout("127.0.0.1",port,List.replicate(U32,32n,73),Fixture.public_key(False{}),Fixture.fixture_alpn(),ms)),
    ~Q.close_shared_quic,~Q.drop_quic_datagram,Wire.Var{4294,4154504685},Wire.Var{4294,4154504686})

def listeners(host: String) -> IO(Unit):
  IdleTest.listeners(~Q.QuicDatagramListener,~Q.DatagramConnection,~bind,~(listener => Fixture.server_accept(9000n,listener)),
    ~(wide => short => IdleTest.serve_pair(~Q.QuicDatagramListener,~Q.DatagramConnection,~Q.step_quic_datagram,~Q.close_quic_connection,~Q.drop_quic_datagram,~Q.close_shared_quic,wide,short)),host)

def checked(ok: Bool, action: Unit -> IO(Unit)) -> IO(Unit):
  match ok:
    case True{}:
      action(Unit{})
    case False{}:
      IO.die(Unit,1,"expected idle-limits or a listener address")

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,host,command]:
      checked(String.eq(command,"idle-listeners"),u => listeners(host))
    case [_,command]:
      checked(String.eq(command,"idle-limits"),u => limits())
    case _:
      IO.die(Unit,1,"expected idle-limits or a listener address")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
