import Base
import ./quic_datagram.bend as Quic
import ./relay_quic.bend as Relay

def Bridge() -> Type:
  Maybe<&1,Relay.Bridge>

def Error() -> Type:
  U32 & String

def Packet() -> Data:
  List<&2,U32>

type Candidate is Type:
  Route{socket: Socket, deadline: Nat, bridge: Bridge()}

type State is Type:
  Waiting{last: Error()}
  Racing{conn: Quic.DatagramConnection, routes: List<&1,Candidate>, first_flight: List<&2,Packet()>, collecting: Bool, last: Error()}
  Connected{conn: Quic.DatagramConnection, bridge: Bridge()}

def stop(bridge: Bridge()) -> IO(Unit):
  match bridge:
    case None{}:
      IO.pure(Unit,Unit{})
    case Some{path}:
      do IO<Unit>:
        _ : Result<&1,&1,U32 & String,Unit> <- Relay.stop(path)
        return Unit{}

def close_routes(routes: List<&1,Candidate>) -> IO(Unit):
  match routes:
    case Nil{}:
      IO.pure(Unit,Unit{})
    case Con{Route{sock,_,bridge},rest}:
      do IO<Unit>:
        Socket.close(sock)
        stop(bridge)
        close_routes(rest)

def fail(conn: Quic.DatagramConnection, routes: List<&1,Candidate>, error: Error()) -> IO(State):
  do IO<State>:
    Quic.drop_quic_datagram(conn)
    close_routes(routes)
    return Waiting{error}

def active(conn: Quic.DatagramConnection, routes: List<&1,Candidate>, flight: List<&2,Packet()>,
    collecting: Bool, last: Error()) -> IO(State):
  match routes:
    case Nil{}:
      fail(conn,[],last)
    case Con{route,rest}:
      IO.pure(State,Racing{conn,Con{route,rest},flight,collecting,last})

def start(result: Result<&1,&1,Error(),Quic.DatagramConnection & Socket>, deadline: Nat, bridge: Bridge()) -> IO(State):
  match result:
    case Done{(conn,sock)}:
      IO.pure(State,Racing{conn,[Route{sock,deadline,bridge}],[],True{},(110,"QUIC datagram handshake timed out")})
    case Fail{error}:
      do IO<State>:
        stop(bridge)
        return Waiting{error}

def Write() -> Type:
  Socket & Poll<&1,&1,Result<&1,&1,Error() & Packet(),Unit>,Packet()>

def Sent() -> Type:
  Socket & Result<&1,&1,Error(),Unit>

# A connected UDP socket accepts one complete datagram per send(2). A full
# send buffer counts as a lost packet for this route. QUIC handles retransmission.
def sent(result: Write()) -> Sent():
  match result:
    case (sock,Ready{Fail{(error,_)}}):
      (sock,Fail{error})
    case (sock,_):
      (sock,Done{Unit{}})

def continue_replay(previous: Sent(), packet: Packet(), next: Sent() -> IO(Sent())) -> IO(Sent()):
  match previous:
    case (sock,Done{_}):
      do IO<Sent()>:
        result : Write() <- TCP.try_send_bytes(sock,packet,0)
        next(sent(result))
    case _:
      IO.pure(Sent(),previous)

def replay(flight: List<&2,Packet()>, previous: Sent()) -> IO(Sent()):
  match flight:
    case Con{packet,rest}:
      continue_replay(previous,packet,next => replay(rest,next))
    case Nil{}:
      IO.pure(Sent(),previous)

def added(result: Sent(), deadline: Nat, bridge: Bridge(), conn: Quic.DatagramConnection,
    routes: List<&1,Candidate>, flight: List<&2,Packet()>, collecting: Bool, last: Error()) -> IO(State):
  match result:
    case (sock,Done{_}):
      IO.pure(State,Racing{conn,Con{Route{sock,deadline,bridge},routes},flight,collecting,last})
    case (sock,Fail{error}):
      do IO<State>:
        Socket.close(sock)
        stop(bridge)
        active(conn,routes,flight,collecting,error)

def opened(result: Result<&1,&1,Error(),Socket>, deadline: Nat, bridge: Bridge(), conn: Quic.DatagramConnection,
    routes: List<&1,Candidate>, +flight: List<&2,Packet()>, collecting: Bool, last: Error()) -> IO(State):
  match result:
    case Done{sock}:
      do IO<State>:
        result : Sent() <- replay(List.reverse(&2,Packet(),flight),(sock,Done{Unit{}}))
        added(result,deadline,bridge,conn,routes,flight,collecting,last)
    case Fail{error}:
      do IO<State>:
        stop(bridge)
        active(conn,routes,flight,collecting,error)

def add(state: State, host: String, port: U32, deadline: Nat, bridge: Bridge(), seed: Packet(), peer: Packet(),
    alpn: Packet()) -> IO(State):
  match state:
    case Waiting{_}:
      do IO<State>:
        result : Result<&1,&1,Error(),Quic.DatagramConnection & Socket> <- Quic.start_route_handshake(host,port,seed,peer,alpn)
        start(result,deadline,bridge)
    case Racing{conn,routes,flight,collecting,last}:
      do IO<State>:
        result : Result<&1,&1,Error(),Socket> <- Quic.open_handshake_socket(host,port)
        opened(result,deadline,bridge,conn,routes,flight,collecting,last)
    case Connected{conn,chosen}:
      do IO<State>:
        stop(bridge)
        return Connected{conn,chosen}

def RoutesResult() -> Type:
  List<&1,Candidate> & Error()

def sent_to(result: Sent(), deadline: Nat, bridge: Bridge(), tail: RoutesResult()) -> IO(RoutesResult()):
  match result:
    case (sock,Done{_}):
      (routes,last) = tail
      IO.pure(RoutesResult(),(Con{Route{sock,deadline,bridge},routes},last))
    case (sock,Fail{error}):
      (routes,_) = tail
      do IO<RoutesResult()>:
        Socket.close(sock)
        stop(bridge)
        return (routes,error)

def broadcast(routes: List<&1,Candidate>, +packet: Packet(), last: Error()) -> IO(RoutesResult()):
  match routes:
    case Nil{}:
      IO.pure(RoutesResult(),([],last))
    case Con{Route{sock,deadline,bridge},rest}:
      do IO<RoutesResult()>:
        result : Write() <- TCP.try_send_bytes(sock,packet,0)
        tail : RoutesResult() <- broadcast(rest,packet,last)
        sent_to(sent(result),deadline,bridge,tail)

def cache_initial(collecting: Bool, packet: Packet(), flight: List<&2,Packet()>) -> List<&2,Packet()>:
  match collecting:
    case True{}:
      Con{packet,flight}
    case False{}:
      flight

def after_broadcast(result: RoutesResult(), conn: Quic.DatagramConnection, flight: List<&2,Packet()>, collecting: Bool) -> IO(State):
  (kept,error) = result
  active(conn,kept,flight,collecting,error)

def emitted(result: Quic.DatagramConnection & Result<&1,&1,Error(),Packet()>, routes: List<&1,Candidate>,
    +flight: List<&2,Packet()>, +collecting: Bool, last: Error()) -> IO(State):
  match result:
    case (conn,Done{Nil{}}):
      IO.pure(State,Racing{conn,routes,flight,collecting && List.is_empty(&2,Packet(),flight),last})
    case (conn,Done{Con{+byte,+rest}}):
      do IO<State>:
        sends : RoutesResult() <- broadcast(routes,Con{byte,rest},last)
        after_broadcast(sends,conn,cache_initial(collecting,Con{byte,rest},flight),collecting)
    case (conn,Fail{error}):
      fail(conn,routes,error)

def output(conn: Quic.DatagramConnection, routes: List<&1,Candidate>, flight: List<&2,Packet()>,
    collecting: Bool, last: Error()) -> IO(State):
  match routes:
    case Nil{}:
      fail(conn,[],last)
    case Con{first,rest}:
      do IO<State>:
        result : Quic.DatagramConnection & Result<&1,&1,Error(),Packet()> <- Quic.route_handshake_output(conn)
        emitted(result,Con{first,rest},flight,collecting,last)

def adopted(result: Quic.DatagramConnection & Result<&1,&1,Error(),Unit>, bridge: Bridge()) -> IO(State):
  match result:
    case (conn,Done{_}):
      IO.pure(State,Connected{conn,bridge})
    case (conn,Fail{error}):
      do IO<State>:
        stop(bridge)
        fail(conn,[],error)

def Input() -> Type:
  Quic.DatagramConnection & (Socket & Result<&1,&1,Error(),U32>)

def Remaining() -> Type:
  Quic.DatagramConnection -> List<&1,Candidate> -> List<&1,Candidate> -> Error() -> IO(State)

def received(result: Input(), deadline: Nat, bridge: Bridge(), rest: List<&1,Candidate>, kept: List<&1,Candidate>,
    last: Error(), resume: Remaining()) -> IO(State):
  match result:
    case (conn,(sock,Done{1})):
      do IO<State>:
        committed : Quic.DatagramConnection & Result<&1,&1,Error(),Unit> <- Quic.adopt_handshake_socket(conn,sock)
        close_routes(rest)
        close_routes(kept)
        adopted(committed,bridge)
    case (conn,(sock,Done{_})):
      resume(conn,rest,Con{Route{sock,deadline,bridge},kept},last)
    case (conn,(sock,Fail{error})):
      do IO<State>:
        Socket.close(sock)
        stop(bridge)
        resume(conn,rest,kept,error)

def examine(expired: Bool, conn: Quic.DatagramConnection, sock: Socket, deadline: Nat, bridge: Bridge(),
    rest: List<&1,Candidate>, kept: List<&1,Candidate>, last: Error(), resume: Remaining()) -> IO(State):
  match expired:
    case True{}:
      do IO<State>:
        Socket.close(sock)
        stop(bridge)
        resume(conn,rest,kept,(110,"QUIC datagram handshake timed out"))
    case False{}:
      do IO<State>:
        result : Input() <- Quic.read_handshake_socket(conn,sock)
        received(result,deadline,bridge,rest,kept,last,resume)

@unsafe def poll(conn: Quic.DatagramConnection, routes: List<&1,Candidate>, kept: List<&1,Candidate>, +now: Nat,
    flight: List<&2,Packet()>, collecting: Bool, last: Error()) -> IO(State):
  match routes:
    case Nil{}:
      output(conn,List.reverse(&1,Candidate,kept),flight,collecting,last)
    case Con{Route{sock,+deadline,bridge},rest}:
      examine(Nat.is_ge(now,deadline),conn,sock,deadline,bridge,rest,kept,last,
        c => todo => done => error => poll(c,todo,done,now,flight,collecting,error))

def step(state: State) -> IO(State):
  match state:
    case Racing{conn,routes,flight,collecting,last}:
      do IO<State>:
        now : Nat <- IO.now()
        poll(conn,routes,[],now,flight,collecting,last)
    case _:
      IO.pure(State,state)
