import Base
import ../src/ed25519.bend as Ed
import ../src/relay.bend as Wire
import ../src/relay_client.bend as Client
import ../src/relay_quic.bend as Relay
import ../src/relay_quic_inbound.bend as Inbound

def checked_port(raw: Socket & Result<&1,&1,U32 & String,U32>) -> IO(Socket & U32):
  match raw:
    case (udp,Done{port}):
      IO.pure(Socket & U32,(udp,port))
    case (_,Fail{(code,message)}):
      IO.die(Socket & U32,code,message)

def socket() -> IO(Socket & U32):
  do IO<Socket & U32>:
    udp : Socket <- IO.try(Socket,UDP.bind("127.0.0.1",0))
    raw : Socket & Result<&1,&1,U32 & String,U32> <- Relay.relay_loopback_port(udp)
    checked_port(raw)

def checked_socket(-T: Type, result: Socket & Result<&1,&1,U32 & String,T>) -> IO(Socket):
  match result:
    case (udp,Done{_}):
      IO.pure(Socket,udp)
    case (_,Fail{(code,message)}):
      IO.die(Socket,code,message)

def send(udp: Socket, port: U32, bytes: List<&2,U32>) -> IO(Socket):
  do IO<Socket>:
    raw : Socket & Result<&1,&1,U32 & String,Unit> <- Relay.local_send(udp,port,bytes)
    checked_socket(Unit,raw)

def enqueue(left: Nat, +seq: U32, udp: Socket, +port: U32, +tag: U32) -> IO(Socket):
  match left:
    case 0n:
      IO.pure(Socket,udp)
    case 1n+rest:
      do IO<Socket>:
        next : Socket <- send(udp,port,[tag,seq])
        enqueue(rest,U32.add(seq,1),next,port,tag)

# Populate the queue before starting the worker. Include one datagram from a
# different local port between the first and second expected packets.
def fill(udp: Socket, +port: U32, +tag: U32, remaining: Nat) -> IO(Socket):
  do IO<Socket>:
    first : Socket <- send(udp,port,[tag,0])
    other : Socket <- IO.try(Socket,UDP.bind("127.0.0.1",0))
    unrelated : Socket <- send(other,port,[255,255])
    Socket.close(unrelated)
    enqueue(remaining,1,first,port,tag)

def verify(packet: Wire.Packet, +source: List<&2,U32>, tag: U32, seq: U32) -> Bool:
  match packet:
    case Wire.Datagram{from,0,0,[group,number]}:
      Relay.equal(from,source) && U32.is_eq(tag,group) && U32.is_eq(seq,number)
    case _:
      False{}

def checked(conn: Client.Connection, ok: Bool, seq: U32) -> IO(Client.Connection):
  match ok:
    case True{}:
      IO.pure(Client.Connection,conn)
    case False{}:
      IO.die(Client.Connection,1,String.append("missing or incorrect queued relay datagram ",U32.show(seq)))

def expect(received: Client.Connection & Wire.Frame, source: List<&2,U32>, tag: U32, +seq: U32) -> IO(Client.Connection):
  (conn,frame) = received
  checked(conn,verify(Wire.packet(frame),source,tag,seq),seq)

def collect(left: Nat, +seq: U32, conn: Client.Connection, +source: List<&2,U32>, +tag: U32) -> IO(Unit):
  match left:
    case 0n:
      Client.close(conn)
    case 1n+rest:
      do IO<Unit>:
        raw : Client.Connection & Wire.Frame <- IO.try(Client.Connection & Wire.Frame,Client.receive(conn))
        checked : Client.Connection <- expect(raw,source,tag,seq)
        collect(rest,U32.add(seq,1),checked,source,tag)

def register(url: String, seed: U32, version: U32) -> IO(Client.Connection):
  IO.try(Client.Connection,Client.connect_with_version(url,List.replicate(U32,32n,seed),version))

def key(seed: U32) -> IO(List<&2,U32>):
  IO.try(List<&2,U32>,Ed.public_key(List.replicate(U32,32n,seed)))

def shutdown() -> IO(Chan(Unit)):
  do IO<Chan(Unit)>:
    +stop : Chan(Unit) <- Chan.new(Unit,0)
    Chan.close(Unit,stop)
    return stop

def stop_outbound(native: Socket & U32, bridge: Socket & U32, sender: Client.Connection, receiver: Client.Connection,
    peer: List<&2,U32>, source: List<&2,U32>) -> IO(Unit):
  (local,port) = native
  (udp,bridge_port) = bridge
  do IO<Unit>:
    queued : Socket <- fill(local,bridge_port,1,95n)
    Socket.close(queued)
    stop : Chan(Unit) <- shutdown()
    IO.try(Unit,Relay.run(Relay.Forwarding{udp,sender,port},peer,stop))
    collect(96n,0,receiver,source,1)
    IO.print("PASS outbound shutdown delivered 96 queued datagrams")

def outbound(+url: String, +version: U32) -> IO(Unit):
  do IO<Unit>:
    receiver : Client.Connection <- register(url,42,version)
    sender : Client.Connection <- register(url,73,version)
    peer : List<&2,U32> <- key(42)
    source : List<&2,U32> <- key(73)
    native : Socket & U32 <- socket()
    bridge : Socket & U32 <- socket()
    stop_outbound(native,bridge,sender,receiver,peer,source)

def stop_inbound(native: Socket & U32, first_route: Socket & U32, second_route: Socket & U32, sender: Client.Connection,
    first: Client.Connection, second: Client.Connection, a: List<&2,U32>, b: List<&2,U32>, +source: List<&2,U32>, url: String) -> IO(Unit):
  (local,port) = native
  (ua,pa) = first_route
  (ub,pb) = second_route
  do IO<Unit>:
    one : Socket <- fill(local,pa,1,11n)
    two : Socket <- fill(one,pb,2,16n)
    Socket.close(two)
    +now : U32 <- Relay.relay_millis()
    stop : Chan(Unit) <- shutdown()
    IO.try(Unit,Inbound.run(Inbound.Online{sender,Inbound.Route{a,ua,now,Inbound.Route{b,ub,now,Inbound.Empty{}}}},100,
      url,List.replicate(U32,32n,73),port,stop))
    collect(12n,0,first,source,1)
    collect(17n,0,second,source,2)
    IO.print("PASS listener shutdown delivered 12 and 17 queued datagrams to the correct peers")

def inbound(+url: String, +version: U32) -> IO(Unit):
  do IO<Unit>:
    first : Client.Connection <- register(url,42,version)
    second : Client.Connection <- register(url,74,version)
    sender : Client.Connection <- register(url,73,version)
    a : List<&2,U32> <- key(42)
    b : List<&2,U32> <- key(74)
    +source : List<&2,U32> <- key(73)
    native : Socket & U32 <- socket()
    first_route : Socket & U32 <- socket()
    second_route : Socket & U32 <- socket()
    stop_inbound(native,first_route,second_route,sender,first,second,a,b,source,url)

def source_port(udp: Socket, ok: Bool) -> IO(Socket):
  match ok:
    case True{}:
      IO.pure(Socket,udp)
    case False{}:
      IO.die(Socket,1,"sealing changed the queued datagram source")

def first_packet(raw: Socket & Poll<&1,&1,Result<&1,&1,U32 & String,String & U32 & List<&2,U32>>,Unit>,
    port: U32) -> IO(Socket):
  match raw:
    case (udp,Ready{Done{(host,from,bytes)}}):
      source_port(udp,String.eq(host,"127.0.0.1") && U32.is_eq(from,port) && Relay.equal(bytes,[7]))
    case _:
      IO.die(Socket,1,"sealing discarded or reordered the queued datagram")

def empty(raw: Socket & Poll<&1,&1,Result<&1,&1,U32 & String,String & U32 & List<&2,U32>>,Unit>) -> IO(Unit):
  match raw:
    case (udp,Wait{_}):
      Socket.close(udp)
    case _:
      IO.die(Unit,1,"a later arrival entered the sealed queue")

def test_seal(native: Socket & U32, bridge: Socket & U32) -> IO(Unit):
  (source,from) = native
  (udp,+port) = bridge
  do IO<Unit>:
    first : Socket <- send(source,port,[7])
    sealed : Socket & Result<&1,&1,U32 & String,U32> <- Relay.relay_seal_loopback(udp)
    live : Socket <- checked_socket(U32,sealed)
    second : Socket <- send(first,port,[8])
    Socket.close(second)
    a : Socket & Poll<&1,&1,Result<&1,&1,U32 & String,String & U32 & List<&2,U32>>,Unit> <- UDP.try_recv_bytes_from(live,64,0)
    drained : Socket <- first_packet(a,from)
    b : Socket & Poll<&1,&1,Result<&1,&1,U32 & String,String & U32 & List<&2,U32>>,Unit> <- UDP.try_recv_bytes_from(drained,64,0)
    empty(b)
    IO.print("PASS sealed loopback socket retained queued data and excluded later arrivals")

def seal() -> IO(Unit):
  do IO<Unit>:
    native : Socket & U32 <- socket()
    bridge : Socket & U32 <- socket()
    test_seal(native,bridge)

def role(name: String, url: String, version: U32) -> IO(Unit):
  match name:
    case "outbound":
      outbound(url,version)
    case "inbound":
      inbound(url,version)
    case _:
      IO.die(Unit,2,"expected outbound or inbound")

def version(value: Maybe<&2,U32>, name: String, url: String) -> IO(Unit):
  match value:
    case Some{1}:
      role(name,url,1)
    case Some{2}:
      role(name,url,2)
    case _:
      IO.die(Unit,2,"expected relay version 1 or 2")

def command(args: List<String>) -> IO(Unit):
  match args:
    case [_,"seal"]:
      seal()
    case [_,url,name,value]:
      version(U32.read(value),name,url)
    case _:
      IO.die(Unit,2,"expected seal or RELAY_URL outbound|inbound 1|2")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    command(args)
