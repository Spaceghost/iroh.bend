import Base
import ../src/endpoint_multipath.bend as Endpoint
import ../src/quic_multipath.bend as Quic
import ../src/quic_multipath_nat.bend as Nat
import ../src/quic_nat.bend as Wire
import ../src/quic_nat_state.bend as State
import ./quic_multipath_bend.bend as Fixture
import ./quic_multipath_listener.bend as Listener

def accept_result(pair: Endpoint.AcceptNatRelayed(),
    retry: Endpoint.NatRelayedListener() -> IO(Endpoint.NatRelayedListener() & Nat.ListenerConnection()))
    -> IO(Endpoint.NatRelayedListener() & Nat.ListenerConnection()):
  match pair:
    case (owner,Done{Some{conn}}):
      IO.pure(Endpoint.NatRelayedListener() & Nat.ListenerConnection(),(owner,conn))
    case (owner,Done{None{}}):
      do IO<Endpoint.NatRelayedListener() & Nat.ListenerConnection()>:
        IO.sleep(1)
        retry(owner)
    case (owner,Fail{(code,message)}):
      do IO<Endpoint.NatRelayedListener() & Nat.ListenerConnection()>:
        _ : Result<&1,&1,U32 & String,Unit> <- Endpoint.close_nat_listener(owner)
        IO.die(Endpoint.NatRelayedListener() & Nat.ListenerConnection(),code,message)

def accept(fuel: Nat, owner: Endpoint.NatRelayedListener()) -> IO(Endpoint.NatRelayedListener() & Nat.ListenerConnection()):
  match fuel:
    case 0n:
      do IO<Endpoint.NatRelayedListener() & Nat.ListenerConnection()>:
        _ : Result<&1,&1,U32 & String,Unit> <- Endpoint.close_nat_listener(owner)
        IO.die(Endpoint.NatRelayedListener() & Nat.ListenerConnection(),1,"NAT listener accept timed out")
    case 1n+left:
      do IO<Endpoint.NatRelayedListener() & Nat.ListenerConnection()>:
        outcome : Endpoint.AcceptNatRelayed() <- Endpoint.accept_nat_listener(owner)
        accept_result(outcome,next => accept(left,next))

def read_initial(outcome: Quic.MultipathConnection & Quic.MultipathRead,
    retry: Quic.MultipathConnection -> IO(Quic.MultipathConnection)) -> IO(Quic.MultipathConnection):
  match outcome:
    case (conn,Quic.MultipathReadBytes{[97]}):
      IO.pure(Quic.MultipathConnection,conn)
    case (conn,Quic.MultipathReadPending{}):
      do IO<Quic.MultipathConnection>:
        IO.sleep(1)
        retry(conn)
    case (conn,_):
      Fixture.reject(Quic.MultipathConnection,conn,1,"expected initial relayed stream data")

def first_byte(fuel: Nat, conn: Quic.MultipathConnection, +stream: U32) -> IO(Quic.MultipathConnection):
  match fuel:
    case 0n:
      Fixture.reject(Quic.MultipathConnection,conn,1,"relayed stream timed out")
    case 1n+left:
      do IO<Quic.MultipathConnection>:
        active : Quic.MultipathConnection <- Fixture.step(conn)
        outcome : Quic.MultipathConnection & Result<&1,&1,U32 & String,Quic.MultipathRead> <-
          Quic.read_multipath_stream(active,stream,1)
        ready : Quic.MultipathConnection & Quic.MultipathRead <- Fixture.ok(Quic.MultipathRead,outcome)
        read_initial(ready,next => first_byte(left,next,stream))

def queue_reply(conn: Quic.MultipathConnection, stream: U32, byte: U32, fin: U32) -> IO(Quic.MultipathConnection):
  do IO<Quic.MultipathConnection>:
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <-
      Quic.write_multipath_stream(conn,stream,[byte],fin)
    queued : Quic.MultipathConnection & U32 <- Fixture.ok(U32,result)
    return Fixture.stepped(queued)

def close_exchange(connection: Quic.MultipathConnection, owner: Endpoint.NatRelayedListener(), +stream: U32) -> IO(Unit):
  do IO<Unit>:
    finished : Quic.MultipathConnection <- Fixture.receive(6000n,connection,stream,99,True{})
    sent : Quic.MultipathConnection <- queue_reply(finished,stream,100,1)
    ack : Quic.MultipathConnection <- Fixture.read_datagram(6000n,sent,[255])
    Quic.close_multipath(ack)
    IO.try(Unit,Endpoint.close_nat_listener(owner))
    IO.print("PASS Bend finished the original accepted stream")

def direct_byte(outcome: Quic.MultipathConnection & Quic.MultipathRead, driver: Nat.ListenerDriver,
    owner: Endpoint.NatRelayedListener(), stream: U32,
    retry: Nat.ListenerConnection() -> Endpoint.NatRelayedListener() -> IO(Unit)) -> IO(Unit):
  match outcome:
    case (conn,Quic.MultipathReadBytes{[99]}):
      close_exchange(conn,owner,stream)
    case (conn,Quic.MultipathReadBytes{[109]}):
      do IO<Unit>:
        sent : Quic.MultipathConnection <- queue_reply(conn,stream,110,0)
        retry((sent,driver),owner)
    case (conn,Quic.MultipathReadPending{}):
      do IO<Unit>:
        IO.sleep(1)
        retry((conn,driver),owner)
    case (conn,_):
      do IO<Unit>:
        _ : Result<&1,&1,U32 & String,Unit> <- Endpoint.close_nat_listener(owner)
        Fixture.reject(Unit,conn,1,"expected the continuation of the original stream")

def progress(outcome: Nat.ListenerProgress(), owner: Endpoint.NatRelayedListener(), +stream: U32,
    retry: Nat.ListenerConnection() -> Endpoint.NatRelayedListener() -> IO(Unit)) -> IO(Unit):
  match outcome:
    case ((conn,driver),Done{_}):
      do IO<Unit>:
        read : Quic.MultipathConnection & Result<&1,&1,U32 & String,Quic.MultipathRead> <- Quic.read_multipath_stream(conn,stream,1)
        ready : Quic.MultipathConnection & Quic.MultipathRead <- Fixture.ok(Quic.MultipathRead,read)
        direct_byte(ready,driver,owner,stream,retry)
    case ((conn,_),Fail{(code,message)}):
      do IO<Unit>:
        _ : Result<&1,&1,U32 & String,Unit> <- Endpoint.close_nat_listener(owner)
        Fixture.reject(Unit,conn,code,message)

def drive(fuel: Nat, connection: Nat.ListenerConnection(), owner: Endpoint.NatRelayedListener(), +stream: U32) -> IO(Unit):
  match fuel:
    case 0n:
      (conn,_) = connection
      do IO<Unit>:
        _ : Result<&1,&1,U32 & String,Unit> <- Endpoint.close_nat_listener(owner)
        Fixture.reject(Unit,conn,1,"NAT path did not carry the original stream")
    case 1n+left:
      do IO<Unit>:
        outcome : Nat.ListenerProgress() <- Nat.step_listener(connection)
        progress(outcome,owner,stream,next => listener => drive(left,next,listener,stream))

def advertised(result: Nat.ListenerConnection() & Result<&1,&1,U32 & String,Unit>,
    owner: Endpoint.NatRelayedListener(), stream: U32) -> IO(Unit):
  match result:
    case (connection,Done{_}):
      # Path setup and Iroh's 15-second direct-path idle timeout share this window.
      drive(45000n,connection,owner,stream)
    case ((conn,_),Fail{(code,message)}):
      do IO<Unit>:
        _ : Result<&1,&1,U32 & String,Unit> <- Endpoint.close_nat_listener(owner)
        Fixture.reject(Unit,conn,code,message)

def start_stream(result: Quic.MultipathConnection & U32, driver: Nat.ListenerDriver,
    owner: Endpoint.NatRelayedListener(), address: State.Candidate) -> IO(Unit):
  (conn,+stream) = result
  do IO<Unit>:
    read : Quic.MultipathConnection <- first_byte(6000n,conn,stream)
    sent : Quic.MultipathConnection <- queue_reply(read,stream,98,0)
    advertised(Nat.advertise_listener((sent,driver),address),owner,stream)

def connected(result: Endpoint.NatRelayedListener() & Nat.ListenerConnection(), address: State.Candidate) -> IO(Unit):
  (owner,(conn,driver)) = result
  do IO<Unit>:
    stream : Quic.MultipathConnection & U32 <- Listener.incoming(6000n,conn,0)
    start_stream(stream,driver,owner,address)

def run_bound(bound: Endpoint.NatRelayedListener() & U32, ip: Wire.Address) -> IO(Unit):
  (owner,+port) = bound
  do IO<Unit>:
    IO.print(String.append("inbound NAT listener ready ",U32.show(port)))
    result : Endpoint.NatRelayedListener() & Nat.ListenerConnection() <- accept(30000n,owner)
    connected(result,State.Socket{ip,port})

def listen(url: String, ip: Wire.Address) -> IO(Unit):
  do IO<Unit>:
    bound : Endpoint.NatRelayedListener() & U32 <- IO.try(Endpoint.NatRelayedListener() & U32,
      Endpoint.bind_nat_listener(0,url,List.replicate(U32,32n,42),[Fixture.text_alpn()],0,8))
    run_bound(bound,ip)

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,url,"127.0.0.2"]:
      listen(url,Wire.IPv4{[127,0,0,2]})
    case [_,url,"::1"]:
      listen(url,Wire.IPv6{[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]})
    case _:
      IO.die(Unit,2,"expected the relay URL and direct candidate IP")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
