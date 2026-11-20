import Base
import ./relay_quic.bend as Relay

def Bridge() -> Type:
  Maybe<&1,Relay.Bridge>

def Error() -> Type:
  U32 & String

def Packet() -> Data:
  List<&2,U32>

def Started(-C: Type) -> Type:
  IO(Result<&1,&1,Error(),C & Socket>)

def Input(-C: Type) -> Type:
  C & (Socket & Result<&1,&1,Error(),U32>)

type Backend<-C: Type> is Type:
  Backend{start: String -> U32 -> Packet() -> Packet() -> Packet() -> Started(C),
    open: String -> U32 -> IO(Result<&1,&1,Error(),Socket>),
    read: C -> Socket -> IO(Input(C)), output: C -> IO(C & Result<&1,&1,Error(),Packet()>),
    adopt: C -> Socket -> IO(C & Result<&1,&1,Error(),Unit>), close: C -> IO(Unit), timeout: String}

def begin(-C: Type, engine: Backend<C>, host: String, port: U32, seed: Packet(), peer: Packet(), alpn: Packet()) -> Started(C):
  Backend{start,_,_,_,_,_,_} = engine
  start(host,port,seed,peer,alpn)

def open_socket(-C: Type, engine: Backend<C>, host: String, port: U32) -> IO(Result<&1,&1,Error(),Socket>):
  Backend{_,open,_,_,_,_,_} = engine
  open(host,port)

def read_input(-C: Type, engine: Backend<C>, conn: C, sock: Socket) -> IO(Input(C)):
  Backend{_,_,read,_,_,_,_} = engine
  read(conn,sock)

def next_packet(-C: Type, engine: Backend<C>, conn: C) -> IO(C & Result<&1,&1,Error(),Packet()>):
  Backend{_,_,_,output,_,_,_} = engine
  output(conn)

def adopt_socket(-C: Type, engine: Backend<C>, conn: C, sock: Socket) -> IO(C & Result<&1,&1,Error(),Unit>):
  Backend{_,_,_,_,adopt,_,_} = engine
  adopt(conn,sock)

def close_engine(-C: Type, engine: Backend<C>, conn: C) -> IO(Unit):
  Backend{_,_,_,_,_,close,_} = engine
  close(conn)

def timeout_error(-C: Type, engine: Backend<C>) -> Error():
  Backend{_,_,_,_,_,_,message} = engine
  (110,message)

type RouteKey is Data:
  DirectKey{host: String, port: U32}
  RelayKey{url: String}

type RouteInfo is Data:
  RouteInfo{deadline: Nat, key: RouteKey}

type Candidate is Type:
  Route{socket: Socket, info: RouteInfo, bridge: Bridge()}

type State<-C: Type> is Type:
  Waiting{last: Error()}
  Racing{conn: C, routes: List<&1,Candidate>, first_flight: List<&2,Packet()>, collecting: Bool, last: Error()}
  Connected{conn: C, bridge: Bridge()}

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

def fail(~C: Type, ~engine: Backend<C>, conn: C, routes: List<&1,Candidate>, error: Error()) -> IO(State<C>):
  do IO<State<C>>:
    close_engine(C,engine,conn)
    close_routes(routes)
    return Waiting{error}

def active(~C: Type, ~engine: Backend<C>, conn: C, routes: List<&1,Candidate>, flight: List<&2,Packet()>,
    collecting: Bool, last: Error()) -> IO(State<C>):
  match routes:
    case Nil{}:
      fail(~C,~engine,conn,[],last)
    case Con{route,rest}:
      IO.pure(State<C>,Racing{conn,Con{route,rest},flight,collecting,last})

def start(~C: Type, ~engine: Backend<C>, result: Result<&1,&1,Error(),C & Socket>, info: RouteInfo, bridge: Bridge()) -> IO(State<C>):
  match result:
    case Done{(conn,sock)}:
      IO.pure(State<C>,Racing{conn,[Route{sock,info,bridge}],[],True{},timeout_error(C,engine)})
    case Fail{error}:
      do IO<State<C>>:
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

def added(~C: Type, ~engine: Backend<C>, result: Sent(), info: RouteInfo, bridge: Bridge(), conn: C,
    routes: List<&1,Candidate>, flight: List<&2,Packet()>, collecting: Bool, last: Error()) -> IO(State<C>):
  match result:
    case (sock,Done{_}):
      IO.pure(State<C>,Racing{conn,Con{Route{sock,info,bridge},routes},flight,collecting,last})
    case (sock,Fail{error}):
      do IO<State<C>>:
        Socket.close(sock)
        stop(bridge)
        active(~C,~engine,conn,routes,flight,collecting,error)

def opened(~C: Type, ~engine: Backend<C>, result: Result<&1,&1,Error(),Socket>, info: RouteInfo, bridge: Bridge(), conn: C,
    routes: List<&1,Candidate>, +flight: List<&2,Packet()>, collecting: Bool, last: Error()) -> IO(State<C>):
  match result:
    case Done{sock}:
      do IO<State<C>>:
        result : Sent() <- replay(List.reverse(&2,Packet(),flight),(sock,Done{Unit{}}))
        added(~C,~engine,result,info,bridge,conn,routes,flight,collecting,last)
    case Fail{error}:
      do IO<State<C>>:
        stop(bridge)
        active(~C,~engine,conn,routes,flight,collecting,error)

def open_route(~C: Type, ~engine: Backend<C>, state: State<C>, host: String, port: U32, info: RouteInfo, bridge: Bridge(), seed: Packet(), peer: Packet(),
    alpn: Packet()) -> IO(State<C>):
  match state:
    case Waiting{_}:
      do IO<State<C>>:
        result : Result<&1,&1,Error(),C & Socket> <- begin(C,engine,host,port,seed,peer,alpn)
        start(~C,~engine,result,info,bridge)
    case Racing{conn,routes,flight,collecting,last}:
      do IO<State<C>>:
        result : Result<&1,&1,Error(),Socket> <- open_socket(C,engine,host,port)
        opened(~C,~engine,result,info,bridge,conn,routes,flight,collecting,last)
    case Connected{conn,chosen}:
      do IO<State<C>>:
        stop(bridge)
        return Connected{conn,chosen}

def add(~C: Type, ~engine: Backend<C>, state: State<C>, +host: String, +port: U32, deadline: Nat, bridge: Bridge(), seed: Packet(), peer: Packet(),
    alpn: Packet()) -> IO(State<C>):
  match bridge:
    case None{}:
      open_route(~C,~engine,state,host,port,RouteInfo{deadline,DirectKey{host,port}},None{},seed,peer,alpn)
    case Some{+path}:
      open_route(~C,~engine,state,host,port,RouteInfo{deadline,RelayKey{Relay.bridge_url(path)}},Some{path},seed,peer,alpn)

def RouteList() -> Type:
  List<&1,Candidate> & List<&2,RouteKey>

def catalog_entry(route: Candidate, tail: RouteList()) -> RouteList():
  Route{socket,RouteInfo{deadline,+key},bridge} = route
  (routes,keys) = tail
  (Con{Route{socket,RouteInfo{deadline,key},bridge},routes},Con{key,keys})

def route_list(routes: List<&1,Candidate>) -> RouteList():
  match routes:
    case Nil{}:
      ([],[])
    case Con{route,tail}:
      catalog_entry(route,route_list(tail))

def Catalog(-C: Type) -> Type:
  State<C> & List<&2,RouteKey>

def racing_routes(-C: Type, list: RouteList(), conn: C, flight: List<&2,Packet()>,
    collecting: Bool, last: Error()) -> Catalog(C):
  (routes,keys) = list
  (Racing{conn,routes,flight,collecting,last},keys)

# Only an open socket suppresses a later discovery of the same address.
def catalog(-C: Type, state: State<C>) -> Catalog(C):
  match state:
    case Racing{conn,routes,flight,collecting,last}:
      racing_routes(C,route_list(routes),conn,flight,collecting,last)
    case _:
      (state,[])

def expired(info: RouteInfo, now: Nat) -> Bool:
  RouteInfo{deadline,_} = info
  Nat.is_ge(now,deadline)

def RoutesResult() -> Type:
  List<&1,Candidate> & Error()

def sent_to(result: Sent(), info: RouteInfo, bridge: Bridge(), tail: RoutesResult()) -> IO(RoutesResult()):
  match result:
    case (sock,Done{_}):
      (routes,last) = tail
      IO.pure(RoutesResult(),(Con{Route{sock,info,bridge},routes},last))
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
    case Con{Route{sock,info,bridge},rest}:
      do IO<RoutesResult()>:
        result : Write() <- TCP.try_send_bytes(sock,packet,0)
        tail : RoutesResult() <- broadcast(rest,packet,last)
        sent_to(sent(result),info,bridge,tail)

def cache_initial(collecting: Bool, packet: Packet(), flight: List<&2,Packet()>) -> List<&2,Packet()>:
  match collecting:
    case True{}:
      Con{packet,flight}
    case False{}:
      flight

def after_broadcast(~C: Type, ~engine: Backend<C>, result: RoutesResult(), conn: C, flight: List<&2,Packet()>, collecting: Bool) -> IO(State<C>):
  (kept,error) = result
  active(~C,~engine,conn,kept,flight,collecting,error)

def emitted(~C: Type, ~engine: Backend<C>, result: C & Result<&1,&1,Error(),Packet()>, routes: List<&1,Candidate>,
    +flight: List<&2,Packet()>, +collecting: Bool, last: Error()) -> IO(State<C>):
  match result:
    case (conn,Done{Nil{}}):
      IO.pure(State<C>,Racing{conn,routes,flight,collecting && List.is_empty(&2,Packet(),flight),last})
    case (conn,Done{Con{+byte,+rest}}):
      do IO<State<C>>:
        sends : RoutesResult() <- broadcast(routes,Con{byte,rest},last)
        after_broadcast(~C,~engine,sends,conn,cache_initial(collecting,Con{byte,rest},flight),collecting)
    case (conn,Fail{error}):
      fail(~C,~engine,conn,routes,error)

def output(~C: Type, ~engine: Backend<C>, conn: C, routes: List<&1,Candidate>, flight: List<&2,Packet()>,
    collecting: Bool, last: Error()) -> IO(State<C>):
  match routes:
    case Nil{}:
      fail(~C,~engine,conn,[],last)
    case Con{first,rest}:
      do IO<State<C>>:
        result : C & Result<&1,&1,Error(),Packet()> <- next_packet(C,engine,conn)
        emitted(~C,~engine,result,Con{first,rest},flight,collecting,last)

def adopted(~C: Type, ~engine: Backend<C>, result: C & Result<&1,&1,Error(),Unit>, bridge: Bridge()) -> IO(State<C>):
  match result:
    case (conn,Done{_}):
      IO.pure(State<C>,Connected{conn,bridge})
    case (conn,Fail{error}):
      do IO<State<C>>:
        stop(bridge)
        fail(~C,~engine,conn,[],error)

def Remaining(-C: Type) -> Type:
  C -> List<&1,Candidate> -> List<&1,Candidate> -> Error() -> IO(State<C>)

def received(~C: Type, ~engine: Backend<C>, result: Input(C), info: RouteInfo, bridge: Bridge(), rest: List<&1,Candidate>, kept: List<&1,Candidate>,
    last: Error(), resume: Remaining(C)) -> IO(State<C>):
  match result:
    case (conn,(sock,Done{1})):
      do IO<State<C>>:
        committed : C & Result<&1,&1,Error(),Unit> <- adopt_socket(C,engine,conn,sock)
        close_routes(rest)
        close_routes(kept)
        adopted(~C,~engine,committed,bridge)
    case (conn,(sock,Done{_})):
      resume(conn,rest,Con{Route{sock,info,bridge},kept},last)
    case (conn,(sock,Fail{error})):
      do IO<State<C>>:
        Socket.close(sock)
        stop(bridge)
        resume(conn,rest,kept,error)

def examine(~C: Type, ~engine: Backend<C>, expired: Bool, conn: C, sock: Socket, info: RouteInfo, bridge: Bridge(),
    rest: List<&1,Candidate>, kept: List<&1,Candidate>, last: Error(), resume: Remaining(C)) -> IO(State<C>):
  match expired:
    case True{}:
      do IO<State<C>>:
        Socket.close(sock)
        stop(bridge)
        resume(conn,rest,kept,timeout_error(C,engine))
    case False{}:
      do IO<State<C>>:
        result : Input(C) <- read_input(C,engine,conn,sock)
        received(~C,~engine,result,info,bridge,rest,kept,last,resume)

@unsafe def poll(~C: Type, ~engine: Backend<C>, conn: C, routes: List<&1,Candidate>, kept: List<&1,Candidate>, +now: Nat,
    flight: List<&2,Packet()>, collecting: Bool, last: Error()) -> IO(State<C>):
  match routes:
    case Nil{}:
      output(~C,~engine,conn,List.reverse(&1,Candidate,kept),flight,collecting,last)
    case Con{Route{sock,+info,bridge},rest}:
      examine(~C,~engine,expired(info,now),conn,sock,info,bridge,rest,kept,last,
        c => todo => done => error => poll(~C,~engine,c,todo,done,now,flight,collecting,error))

def step(~C: Type, ~engine: Backend<C>, state: State<C>) -> IO(State<C>):
  match state:
    case Racing{conn,routes,flight,collecting,last}:
      do IO<State<C>>:
        now : Nat <- IO.now()
        poll(~C,~engine,conn,routes,[],now,flight,collecting,last)
    case _:
      IO.pure(State<C>,state)
