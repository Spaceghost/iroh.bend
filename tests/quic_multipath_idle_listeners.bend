import Base
import ./quic_idle_listeners.bend as IdleTest
import ../src/quic_nat.bend as Wire
import ../src/quic_multipath.bend as Q
import ./quic_multipath_bend.bend as Fixture
import ./quic_multipath_listener.bend as Listener
import ../src/endpoint.bend as BaseEndpoint
import ../src/endpoint_multipath.bend as Endpoint

def bind(host: String, idle_ms: Wire.VarInt) -> IO(Result<&1,&1,U32 & String,Q.MultipathListener & U32>):
  Endpoint.bind_with_idle_timeout(BaseEndpoint.IpAddress{host,0},
    BaseEndpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.fixture_key(0),Fixture.text_alpn()},idle_ms)

def limits() -> IO(Unit):
  IdleTest.limits(~Q.MultipathListener,~Q.MultipathConnection,
    ~(ms => bind("127.0.0.1",ms)),
    ~(port => ms => Q.start_multipath_bytes_with_idle_timeout("127.0.0.1",port,List.replicate(U32,32n,73),Fixture.fixture_key(0),Fixture.text_alpn(),ms)),
    ~Q.close_multipath_listener,~Q.close_multipath,Wire.Var{4294967,1271310319},Wire.Var{4294967,1271310320})

def listeners(host: String) -> IO(Unit):
  IdleTest.listeners(~Q.MultipathListener,~Q.MultipathConnection,~bind,~(listener => Listener.accept(9000n,listener)),
    ~(wide => short => IdleTest.serve_pair(~Q.MultipathListener,~Q.MultipathConnection,~Q.step_multipath,~Q.close_multipath_connection,~Q.close_multipath,~Q.close_multipath_listener,wide,short)),host)

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
