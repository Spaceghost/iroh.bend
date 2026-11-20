import Base
import ./relay.bend as Wire
import ./relay_client.bend as Client
import ./direct.bend as Direct

type Bridge is Data:
  RelayPath{shutdown: Chan(Unit), finished: Chan(Result<&1,&1,U32 & String,Unit>), url: String}

type Flow is Type:
  Forwarding{udp: Socket, relay: Client.Connection, port: U32}
  Ended{result: Result<&1,&1,U32 & String,Unit>}

type Segment is Data:
  Payload{bytes: List<&2,U32>, tail: List<&2,U32>}

def relay_loopback_port(socket: Socket) -> IO(Socket & Result<&1,&1,U32 & String,U32>):
  import "./relay_quic.c"

def relay_seal_loopback(socket: Socket) -> IO(Socket & Result<&1,&1,U32 & String,U32>):
  import "./relay_quic.c"

def relay_millis() -> IO(U32):
  import "./relay_quic.c"

def equal(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(x,y) && equal(xs,ys)
    case _ _:
      False{}

def cut(size: Nat, packet: List<&2,U32>, reversed: List<&2,U32>) -> Segment:
  match size packet:
    case 1n+left Con{byte,tail}:
      cut(left,tail,Con{byte,reversed})
    case _ _:
      Payload{List.reverse(&2,U32,reversed),packet}

def udp_result(sent: Socket & Result<&1,&1,(U32 & String) & List<&2,U32>,Unit>)
    -> Socket & Result<&1,&1,U32 & String,Unit>:
  match sent:
    case (udp,Done{unit}):
      (udp,Done{unit})
    case (udp,Fail{(error,_)}):
      (udp,Fail{error})

def local_send(udp: Socket, port: U32, bytes: List<&2,U32>)
    -> IO(Socket & Result<&1,&1,U32 & String,Unit>):
  do IO<Socket & Result<&1,&1,U32 & String,Unit>>:
    sent : Socket & Result<&1,&1,(U32 & String) & List<&2,U32>,Unit> <-
      UDP.send_bytes_to(udp,"127.0.0.1",port,bytes)
    return udp_result(sent)

def next_chunk(result: Socket & Result<&1,&1,U32 & String,Unit>, tail: List<&2,U32>,
    resume: Socket -> List<&2,U32> -> IO(Socket & Result<&1,&1,U32 & String,Unit>))
    -> IO(Socket & Result<&1,&1,U32 & String,Unit>):
  match result:
    case (udp,Done{_}):
      resume(udp,tail)
    case (udp,Fail{error}):
      IO.pure(Socket & Result<&1,&1,U32 & String,Unit>,(udp,Fail{error}))

def send_chunk(part: Segment, udp: Socket, port: U32,
    resume: Socket -> List<&2,U32> -> IO(Socket & Result<&1,&1,U32 & String,Unit>))
    -> IO(Socket & Result<&1,&1,U32 & String,Unit>):
  Payload{first,rest} = part
  do IO<Socket & Result<&1,&1,U32 & String,Unit>>:
    sent : Socket & Result<&1,&1,U32 & String,Unit> <- local_send(udp,port,first)
    next_chunk(sent,rest,resume)

def chunked(+fuel: Nat, udp: Socket, +port: U32, +size: Nat, bytes: List<&2,U32>)
    -> IO(Socket & Result<&1,&1,U32 & String,Unit>):
  match fuel bytes:
    case _ Nil{}:
      IO.pure(Socket & Result<&1,&1,U32 & String,Unit>,(udp,Done{Unit{}}))
    case 0n _:
      IO.pure(Socket & Result<&1,&1,U32 & String,Unit>,(udp,Fail{(1,"relay batch exceeds 64 UDP datagrams")}))
    case 1n+left Con{head,tail}:
      send_chunk(cut(size,Con{head,tail},[]),udp,port,next => remaining => chunked(left,next,port,size,remaining))

def local_packet(udp: Socket, port: U32, segment: U32, bytes: List<&2,U32>)
    -> IO(Socket & Result<&1,&1,U32 & String,Unit>):
  match segment:
    case 0:
      local_send(udp,port,bytes)
    case _:
      chunked(64n,udp,port,U32.to_nat(segment),bytes)

def fail_local(udp: Socket, error: U32 & String) -> IO(Flow):
  do IO<Flow>:
    Socket.close(udp)
    return Ended{Fail{error}}

def fail_both(udp: Socket, relay: Client.Connection, error: U32 & String) -> IO(Flow):
  do IO<Flow>:
    Client.close(relay)
    fail_local(udp,error)

def advanced(udp: Socket, port: U32, reply: Result<&1,&1,U32 & String,Client.Connection>) -> IO(Flow):
  match reply:
    case Done{conn}:
      IO.pure(Flow,Forwarding{udp,conn,port})
    case Fail{error}:
      fail_local(udp,error)

def udp_forwarded(result: Socket & Result<&1,&1,U32 & String,Unit>, relay: Client.Connection, port: U32) -> IO(Flow):
  match result:
    case (udp,Done{_}):
      IO.pure(Flow,Forwarding{udp,relay,port})
    case (udp,Fail{error}):
      fail_both(udp,relay,error)

def forward_data(udp: Socket, relay: Client.Connection, +port: U32, segment: U32,
    bytes: List<&2,U32>, allowed: Bool) -> IO(Flow):
  match allowed:
    case False{}:
      IO.pure(Flow,Forwarding{udp,relay,port})
    case True{}:
      do IO<Flow>:
        sent : Socket & Result<&1,&1,U32 & String,Unit> <- local_packet(udp,port,segment,bytes)
        udp_forwarded(sent,relay,port)

def forward_packet(udp: Socket, relay: Client.Connection, +port: U32, peer: List<&2,U32>, pkt: Wire.Packet) -> IO(Flow):
  match pkt:
    case Wire.Datagram{from,_,segment,bytes}:
      forward_data(udp,relay,port,segment,bytes,U32.is_gt(port,0) && equal(from,peer))
    case _:
      IO.pure(Flow,Forwarding{udp,relay,port})

def relay_input(udp: Socket, port: U32, peer: List<&2,U32>,
    received: Result<&1,&1,U32 & String,Client.Connection & Maybe<&1,Wire.Frame>>) -> IO(Flow):
  match received:
    case Fail{error}:
      fail_local(udp,error)
    case Done{(relay,Some{Wire.Message{9,payload}})}:
      do IO<Flow>:
        pong : Result<&1,&1,U32 & String,Client.Connection> <- Client.pong(relay,payload)
        advanced(udp,port,pong)
    case Done{(relay,Some{frame})}:
      forward_packet(udp,relay,port,peer,Wire.packet(frame))
    case Done{(relay,None{})}:
      IO.pure(Flow,Forwarding{udp,relay,port})

def read_relay(pipe: Flow, peer: List<&2,U32>, ms: U32) -> IO(Flow):
  match pipe:
    case Ended{result}:
      IO.pure(Flow,Ended{result})
    case Forwarding{udp,relay,port}:
      do IO<Flow>:
        received : Result<&1,&1,U32 & String,Client.Connection & Maybe<&1,Wire.Frame>> <- Client.try_receive(relay,ms)
        relay_input(udp,port,peer,received)

def route_local(-T: Type, relay: Client.Connection, port: U32, +from: U32, peer: List<&2,U32>,
    data: List<&2,U32>, allowed: Bool, next: U32 -> Result<&1,&1,U32 & String,Client.Connection> -> IO(T)) -> IO(T):
  match allowed:
    case False{}:
      next(port,Done{relay})
    case True{}:
      do IO<T>:
        sent : Result<&1,&1,U32 & String,Client.Connection> <- Client.send_datagram(relay,peer,0,0,data)
        next(from,sent)

def send_relay(udp: Socket, relay: Client.Connection, port: U32, from: U32, peer: List<&2,U32>,
    data: List<&2,U32>, allowed: Bool) -> IO(Flow):
  route_local(Flow,relay,port,from,peer,data,allowed,dest => reply => advanced(udp,dest,reply))

def local_source(host: String, +from: U32, +port: U32) -> Bool:
  String.eq(host,"127.0.0.1") && (U32.is_eq(port,0) || U32.is_eq(port,from))

def forward_local(udp: Socket, relay: Client.Connection, +port: U32, peer: List<&2,U32>,
    host: String, +from: U32, data: List<&2,U32>) -> IO(Flow):
  send_relay(udp,relay,port,from,peer,data,local_source(host,from,port))

def local_input(packet: Socket & Poll<&1,&1,Result<&1,&1,U32 & String,String & U32 & List<&2,U32>>,Unit>,
    relay: Client.Connection, +port: U32, +peer: List<&2,U32>) -> IO(Flow):
  match packet:
    case (udp,Wait{_}):
      read_relay(Forwarding{udp,relay,port},peer,3)
    case (udp,Ready{Fail{error}}):
      fail_both(udp,relay,error)
    case (udp,Ready{Done{(host,+from,data)}}):
      do IO<Flow>:
        outgoing : Flow <- forward_local(udp,relay,port,peer,host,from,data)
        read_relay(outgoing,peer,0)

def stop_flow(udp: Socket, relay: Client.Connection) -> IO(Result<&1,&1,U32 & String,Unit>):
  do IO<Result<&1,&1,U32 & String,Unit>>:
    Socket.close(udp)
    Client.close(relay)
    return Done{Unit{}}

def DrainResult() -> Type:
  Result<&1,&1,U32 & String,Client.Connection>

def drain_error(udp: Socket, relay: Client.Connection, error: U32 & String) -> IO(DrainResult()):
  do IO<DrainResult()>:
    _ : Result<&1,&1,U32 & String,Unit> <- stop_flow(udp,relay)
    return Fail{error}

def drain_sent(udp: Socket, port: U32, result: DrainResult(),
    next: Socket -> Client.Connection -> U32 -> IO(DrainResult())) -> IO(DrainResult()):
  match result:
    case Done{relay}:
      next(udp,relay,port)
    case Fail{error}:
      do IO<DrainResult()>:
        Socket.close(udp)
        return Fail{error}

def drain_packet(packet: Socket & Poll<&1,&1,Result<&1,&1,U32 & String,String & U32 & List<&2,U32>>,Unit>,
    relay: Client.Connection, +port: U32, peer: List<&2,U32>,
    next: Socket -> Client.Connection -> U32 -> IO(DrainResult())) -> IO(DrainResult()):
  match packet:
    case (udp,Wait{_}):
      do IO<DrainResult()>:
        Socket.close(udp)
        return Done{relay}
    case (udp,Ready{Fail{error}}):
      drain_error(udp,relay,error)
    case (udp,Ready{Done{(host,+from,data)}}):
      route_local(DrainResult(),relay,port,from,peer,data,local_source(host,from,port),
        dest => reply => drain_sent(udp,dest,reply,next))

# The private socket admits no further packets after sealing. Drain the FIFO
# through EAGAIN and keep the shared relay session alive for the next peer.
@unsafe def drain_queued(udp: Socket, relay: Client.Connection, port: U32, +peer: List<&2,U32>) -> IO(DrainResult()):
  do IO<DrainResult()>:
    packet : Socket & Poll<&1,&1,Result<&1,&1,U32 & String,String & U32 & List<&2,U32>>,Unit> <-
      UDP.try_recv_bytes_from(udp,65507,0)
    drain_packet(packet,relay,port,peer,socket => conn => dest => drain_queued(socket,conn,dest,peer))

def sealed(result: Socket & Result<&1,&1,U32 & String,U32>, relay: Client.Connection, port: U32,
    peer: List<&2,U32>) -> IO(DrainResult()):
  match result:
    case (udp,Done{_}):
      drain_queued(udp,relay,port,peer)
    case (udp,Fail{error}):
      drain_error(udp,relay,error)

def drain_peer(udp: Socket, relay: Client.Connection, port: U32, peer: List<&2,U32>) -> IO(DrainResult()):
  do IO<DrainResult()>:
    result : Socket & Result<&1,&1,U32 & String,U32> <- relay_seal_loopback(udp)
    sealed(result,relay,port,peer)

def close_drained(result: DrainResult()) -> IO(Result<&1,&1,U32 & String,Unit>):
  match result:
    case Done{relay}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        Client.close(relay)
        return Done{Unit{}}
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Unit>,Fail{error})

def after_stop(udp: Socket, relay: Client.Connection, port: U32, peer: List<&2,U32>,
    poll: Poll<&1,&1,Maybe<&1,Unit>,Unit>, advance: Flow -> IO(Result<&1,&1,U32 & String,Unit>))
    -> IO(Result<&1,&1,U32 & String,Unit>):
  match poll:
    case Ready{_}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        drained : DrainResult() <- drain_peer(udp,relay,port,peer)
        close_drained(drained)
    case Wait{_}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        packet : Socket & Poll<&1,&1,Result<&1,&1,U32 & String,String & U32 & List<&2,U32>>,Unit> <-
          UDP.try_recv_bytes_from(udp,65507,0)
        flow : Flow <- local_input(packet,relay,port,peer)
        advance(flow)

# The bridge runs until the owner closes its channel or a socket fails.
@unsafe def run(flow: Flow, +peer: List<&2,U32>, +shutdown: Chan(Unit)) -> IO(Result<&1,&1,U32 & String,Unit>):
  match flow:
    case Ended{result}:
      IO.pure(Result<&1,&1,U32 & String,Unit>,result)
    case Forwarding{udp,relay,port}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        requested : Poll<&1,&1,Maybe<&1,Unit>,Unit> <- Chan.try_recv(Unit,shutdown,0)
        after_stop(udp,relay,port,peer,requested,next => run(next,peer,shutdown))

def bound_port(handle: Socket & Result<&1,&1,U32 & String,U32>, relay: Client.Connection,
    peer: List<&2,U32>, destination: U32, url: String) -> IO(Result<&1,&1,U32 & String,Bridge & U32>):
  match handle:
    case (udp,Fail{error}):
      do IO<Result<&1,&1,U32 & String,Bridge & U32>>:
        Socket.close(udp)
        Client.close(relay)
        return Fail{error}
    case (udp,Done{port}):
      do IO<Result<&1,&1,U32 & String,Bridge & U32>>:
        +shutdown : Chan(Unit) <- Chan.new(Unit,0)
        finished : Chan(Result<&1,&1,U32 & String,Unit>) <- IO.fork(Result<&1,&1,U32 & String,Unit>,
          run(Forwarding{udp,relay,destination},peer,shutdown))
        return Done{(RelayPath{shutdown,finished,url},port)}

def attached(relay: Result<&1,&1,U32 & String,Client.Connection>, udp: Socket,
    peer: List<&2,U32>, port: U32, url: String) -> IO(Result<&1,&1,U32 & String,Bridge & U32>):
  match relay:
    case Fail{error}:
      do IO<Result<&1,&1,U32 & String,Bridge & U32>>:
        Socket.close(udp)
        return Fail{error}
    case Done{connected}:
      do IO<Result<&1,&1,U32 & String,Bridge & U32>>:
        info : Socket & Result<&1,&1,U32 & String,U32> <- relay_loopback_port(udp)
        bound_port(info,connected,peer,port,url)

def connect(bound: Result<&1,&1,U32 & String,Socket>, +url: String, seed: List<&2,U32>,
    peer: List<&2,U32>, port: U32) -> IO(Result<&1,&1,U32 & String,Bridge & U32>):
  match bound:
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Bridge & U32>,Fail{error})
    case Done{udp}:
      do IO<Result<&1,&1,U32 & String,Bridge & U32>>:
        relay : Result<&1,&1,U32 & String,Client.Connection> <- Client.connect(url,seed)
        attached(relay,udp,peer,port,url)

def start_checked(size: Wire.Size, valid_port: Bool, url: String, seed: List<&2,U32>,
    peer: List<&2,U32>, local_port: U32)
    -> IO(Result<&1,&1,U32 & String,Bridge & U32>):
  match size valid_port:
    case Wire.Length{32} True{}:
      do IO<Result<&1,&1,U32 & String,Bridge & U32>>:
        bound : Result<&1,&1,U32 & String,Socket> <- UDP.bind("127.0.0.1",0)
        connect(bound,url,seed,peer,local_port)
    case _ _:
      IO.pure(Result<&1,&1,U32 & String,Bridge & U32>,Fail{(1,"invalid relay peer key or local port")})

# Open a local UDP path to the pinned relay peer. For a listening QUIC
# socket set local_port to its port. For dialing use 0 and send first.
def start(url: String, seed: List<&2,U32>, +peer: List<&2,U32>, +local_port: U32)
    -> IO(Result<&1,&1,U32 & String,Bridge & U32>):
  start_checked(Wire.measure_limited(peer,32),U32.is_le(local_port,65535),url,seed,peer,local_port)

def bridge_url(bridge: Bridge) -> String:
  RelayPath{_,_,url} = bridge
  url

def stop(bridge: Bridge) -> IO(Result<&1,&1,U32 & String,Unit>):
  RelayPath{shutdown,finished,_} = bridge
  do IO<Result<&1,&1,U32 & String,Unit>>:
    Chan.close(Unit,shutdown)
    IO.join(Result<&1,&1,U32 & String,Unit>,finished)

def connected_relayed(outcome: Result<&1,&1,U32 & String,Direct.QuicConnection>, bridge: Bridge)
    -> IO(Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Bridge>>):
  match outcome:
    case Done{conn}:
      IO.pure(Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Bridge>>,Done{(conn,Some{bridge})})
    case Fail{error}:
      do IO<Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Bridge>>>:
        _ : Result<&1,&1,U32 & String,Unit> <- stop(bridge)
        return Fail{error}

def dial_attached(outcome: Result<&1,&1,U32 & String,Bridge & U32>, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, relay_ms: U32)
    -> IO(Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Bridge>>):
  match outcome:
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Bridge>>,Fail{error})
    case Done{(bridge,port)}:
      do IO<Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Bridge>>>:
        relayed : Result<&1,&1,U32 & String,Direct.QuicConnection> <-
          Direct.quic_connect_with_timeout("127.0.0.1",port,seed,peer,alpn,relay_ms)
        connected_relayed(relayed,bridge)

def selected_dial(direct: Result<&1,&1,U32 & String,Direct.QuicConnection>, relay_url: String, relay_ms: U32,
    +seed: List<&2,U32>, +peer: List<&2,U32>, alpn: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Bridge>>):
  match direct:
    case Done{conn}:
      IO.pure(Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Bridge>>,Done{(conn,None{})})
    case Fail{_}:
      do IO<Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Bridge>>>:
        attached : Result<&1,&1,U32 & String,Bridge & U32> <- start(relay_url,seed,peer,0)
        dial_attached(attached,seed,peer,alpn,relay_ms)

# Select a path before returning a connection to the application. A returned
# bridge belongs to the connection and can be stopped after closing QUIC.
def dial_with_fallback(host: String, port: U32, direct_ms: U32, relay_url: String, relay_ms: U32,
    +seed: List<&2,U32>, +peer: List<&2,U32>, +alpn: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Bridge>>):
  do IO<Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Bridge>>>:
    direct : Result<&1,&1,U32 & String,Direct.QuicConnection> <-
      Direct.quic_connect_with_timeout(host,port,seed,peer,alpn,direct_ms)
    selected_dial(direct,relay_url,relay_ms,seed,peer,alpn)
