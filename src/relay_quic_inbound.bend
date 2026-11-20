import Base
import ./relay.bend as Wire
import ./relay_client.bend as Client
import ./relay_quic.bend as Relay

# Each authenticated relay sender has its own local UDP source tuple.
type Routes is Type:
  Empty{}
  Route{peer: List<&2,U32>, udp: Socket, activity: U32, rest: Routes}

type State is Type:
  Online{relay: Client.Connection, routes: Routes}
  Offline{routes: Routes}

def close_routes(routes: Routes) -> IO(Unit):
  match routes:
    case Empty{}:
      IO.pure(Unit,Unit{})
    case Route{_,udp,_,rest}:
      do IO<Unit>:
        Socket.close(udp)
        close_routes(rest)

def append_route(state: State, peer: List<&2,U32>, udp: Socket, activity: U32) -> State:
  match state:
    case Online{relay,rest}:
      Online{relay,Route{peer,udp,activity,rest}}
    case Offline{rest}:
      Offline{Route{peer,udp,activity,rest}}

def forwarded(result: Socket & Result<&1,&1,U32 & String,Unit>, peer: List<&2,U32>,
    rest: Routes, now: U32) -> Routes:
  (udp,_) = result
  Route{peer,udp,now,rest}

def forward(udp: Socket, port: U32, segment: U32, bytes: List<&2,U32>, peer: List<&2,U32>,
    rest: Routes, now: U32) -> IO(Routes):
  do IO<Routes>:
    sent : Socket & Result<&1,&1,U32 & String,Unit> <- Relay.local_packet(udp,port,segment,bytes)
    return forwarded(sent,peer,rest,now)

def attach(bound: Result<&1,&1,U32 & String,Socket>, port: U32, segment: U32, bytes: List<&2,U32>,
    peer: List<&2,U32>, now: U32) -> IO(Routes):
  match bound:
    case Done{udp}:
      forward(udp,port,segment,bytes,peer,Empty{},now)
    case Fail{_}:
      IO.pure(Routes,Empty{})

def route_packet(found: Bool, udp: Socket, activity: U32, key: List<&2,U32>, rest: Routes,
    peer: List<&2,U32>, port: U32, segment: U32, bytes: List<&2,U32>, now: U32,
    next: Routes -> List<&2,U32> -> IO(Routes)) -> IO(Routes):
  match found:
    case True{}:
      forward(udp,port,segment,bytes,peer,rest,now)
    case False{}:
      do IO<Routes>:
        remainder : Routes <- next(rest,bytes)
        return Route{key,udp,activity,remainder}

def insert_route(fuel: Nat, route: Routes, +port: U32, +peer: List<&2,U32>, +segment: U32,
    bytes: List<&2,U32>, +now: U32) -> IO(Routes):
  match fuel route:
    case 0n current:
      IO.pure(Routes,current)
    case 1n+_ Empty{}:
      do IO<Routes>:
        bound : Result<&1,&1,U32 & String,Socket> <- UDP.bind("127.0.0.1",0)
        attach(bound,port,segment,bytes,peer,now)
    case 1n+left Route{+key,udp,activity,rest}:
      route_packet(Relay.equal(key,peer),udp,activity,key,rest,peer,port,segment,bytes,now,
        remaining => payload => insert_route(left,remaining,port,peer,segment,payload,now))

def after_relay(sent: Result<&1,&1,U32 & String,Client.Connection>, rest: Routes,
    next: Client.Connection -> Routes -> IO(State)) -> IO(State):
  match sent:
    case Done{relay}:
      next(relay,rest)
    case Fail{_}:
      IO.pure(State,Offline{rest})

def outbound(matches: Bool, udp: Socket, relay: Client.Connection, +peer: List<&2,U32>, rest: Routes,
    activity: U32, now: U32, bytes: List<&2,U32>, next: Client.Connection -> Routes -> IO(State)) -> IO(State):
  match matches:
    case False{}:
      do IO<State>:
        swept : State <- next(relay,rest)
        return append_route(swept,peer,udp,activity)
    case True{}:
      do IO<State>:
        sent : Result<&1,&1,U32 & String,Client.Connection> <- Client.send_datagram(relay,peer,0,0,bytes)
        swept : State <- after_relay(sent,rest,next)
        return append_route(swept,peer,udp,now)

def local_input(result: Socket & Poll<&1,&1,Result<&1,&1,U32 & String,String & U32 & List<&2,U32>>,Unit>,
    relay: Client.Connection, peer: List<&2,U32>, rest: Routes, activity: U32, port: U32, now: U32,
    next: Client.Connection -> Routes -> IO(State)) -> IO(State):
  match result:
    case (udp,Wait{_}):
      do IO<State>:
        swept : State <- next(relay,rest)
        return append_route(swept,peer,udp,activity)
    case (udp,Ready{Fail{_}}):
      do IO<State>:
        Socket.close(udp)
        next(relay,rest)
    case (udp,Ready{Done{(host,from,bytes)}}):
      outbound(String.eq(host,"127.0.0.1") && U32.is_eq(from,port),udp,relay,peer,rest,activity,now,bytes,next)

def poll_route(expired: Bool, udp: Socket, relay: Client.Connection, peer: List<&2,U32>, rest: Routes,
    activity: U32, port: U32, now: U32, next: Client.Connection -> Routes -> IO(State)) -> IO(State):
  match expired:
    case True{}:
      do IO<State>:
        Socket.close(udp)
        next(relay,rest)
    case False{}:
      do IO<State>:
        polled : Socket & Poll<&1,&1,Result<&1,&1,U32 & String,String & U32 & List<&2,U32>>,Unit> <-
          UDP.try_recv_bytes_from(udp,65507,0)
        local_input(polled,relay,peer,rest,activity,port,now,next)

def sweep(fuel: Nat, routes: Routes, relay: Client.Connection, +port: U32, +now: U32) -> IO(State):
  match fuel routes:
    case 1n+left Route{peer,udp,+activity,rest}:
      poll_route(U32.is_ge(U32.sub(now,activity),120000),udp,relay,peer,rest,activity,port,now,
        conn => remaining => sweep(left,remaining,conn,port,now))
    case _ current:
      IO.pure(State,Online{relay,current})

def receive_packet(packet: Wire.Packet, relay: Client.Connection, routes: Routes, port: U32, now: U32) -> IO(State):
  match packet:
    case Wire.Datagram{peer,_,segment,bytes}:
      do IO<State>:
        updated : Routes <- insert_route(64n,routes,port,peer,segment,bytes,now)
        return Online{relay,updated}
    case _:
      IO.pure(State,Online{relay,routes})

def relay_result(result: Result<&1,&1,U32 & String,Client.Connection & Maybe<&1,Wire.Frame>>,
    routes: Routes, port: U32, now: U32) -> IO(State):
  match result:
    case Done{(relay,Some{Wire.Message{9,payload}})}:
      do IO<State>:
        pong : Result<&1,&1,U32 & String,Client.Connection> <- Client.pong(relay,payload)
        after_relay(pong,routes,conn => remaining => IO.pure(State,Online{conn,remaining}))
    case Done{(relay,Some{frame})}:
      receive_packet(Wire.packet(frame),relay,routes,port,now)
    case Done{(relay,None{})}:
      IO.pure(State,Online{relay,routes})
    case Fail{_}:
      IO.pure(State,Offline{routes})

def finish(state: State) -> IO(Result<&1,&1,U32 & String,Unit>):
  match state:
    case Offline{routes}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        close_routes(routes)
        return Done{Unit{}}
    case Online{relay,routes}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        close_routes(routes)
        Client.close(relay)
        return Done{Unit{}}

def receive(state: State, port: U32, now: U32) -> IO(State):
  match state:
    case Offline{routes}:
      IO.pure(State,Offline{routes})
    case Online{relay,routes}:
      do IO<State>:
        received : Result<&1,&1,U32 & String,Client.Connection & Maybe<&1,Wire.Frame>> <- Client.try_receive(relay,2)
        relay_result(received,routes,port,now)

def advance(stop: Poll<&1,&1,Maybe<&1,Unit>,Unit>, state: State, port: U32, now: U32,
    next: State -> U32 -> IO(Result<&1,&1,U32 & String,Unit>)) -> IO(Result<&1,&1,U32 & String,Unit>):
  match stop:
    case Ready{_}:
      finish(state)
    case Wait{_}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        updated : State <- receive(state,port,now)
        next(updated,100)

def cycle(stop: Poll<&1,&1,Maybe<&1,Unit>,Unit>, relay: Client.Connection, routes: Routes, +port: U32,
    next: State -> U32 -> IO(Result<&1,&1,U32 & String,Unit>)) -> IO(Result<&1,&1,U32 & String,Unit>):
  do IO<Result<&1,&1,U32 & String,Unit>>:
    +now : U32 <- Relay.relay_millis()
    swept : State <- sweep(64n,routes,relay,port,now)
    advance(stop,swept,port,now,next)

def reconnected(result: Result<&1,&1,U32 & String,Client.Connection>, routes: Routes, delay: U32,
    next: State -> U32 -> IO(Result<&1,&1,U32 & String,Unit>)) -> IO(Result<&1,&1,U32 & String,Unit>):
  match result:
    case Done{relay}:
      next(Online{relay,routes},100)
    case Fail{_}:
      next(Offline{routes},U32.min(U32.mul(delay,2),5000))

def reconnect(stop: Poll<&1,&1,Maybe<&1,Unit>,Unit>, routes: Routes, delay: U32, url: String, seed: List<&2,U32>,
    next: State -> U32 -> IO(Result<&1,&1,U32 & String,Unit>)) -> IO(Result<&1,&1,U32 & String,Unit>):
  match stop:
    case Ready{_}:
      finish(Offline{routes})
    case Wait{_}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        result : Result<&1,&1,U32 & String,Client.Connection> <- Client.connect(url,seed)
        reconnected(result,routes,delay,next)

# Retain route sockets across an outage so QUIC still sees the same source tuple.
@unsafe def run(state: State, +delay: U32, +url: String, +seed: List<&2,U32>, +port: U32, +shutdown: Chan(Unit))
    -> IO(Result<&1,&1,U32 & String,Unit>):
  match state:
    case Offline{routes}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        stop : Poll<&1,&1,Maybe<&1,Unit>,Unit> <- Chan.try_recv(Unit,shutdown,delay)
        reconnect(stop,routes,delay,url,seed,updated => ms => run(updated,ms,url,seed,port,shutdown))
    case Online{relay,routes}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        stop : Poll<&1,&1,Maybe<&1,Unit>,Unit> <- Chan.try_recv(Unit,shutdown,0)
        cycle(stop,relay,routes,port,updated => ms => run(updated,ms,url,seed,port,shutdown))

def start_connected(result: Result<&1,&1,U32 & String,Client.Connection>, port: U32, +url: String, seed: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,Relay.Bridge>):
  match result:
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Relay.Bridge>,Fail{error})
    case Done{relay}:
      do IO<Result<&1,&1,U32 & String,Relay.Bridge>>:
        +shutdown : Chan(Unit) <- Chan.new(Unit,0)
        finished : Chan(Result<&1,&1,U32 & String,Unit>) <- IO.fork(Result<&1,&1,U32 & String,Unit>,
          run(Online{relay,Empty{}},100,url,seed,port,shutdown))
        return Done{Relay.RelayPath{shutdown,finished,url}}

def start_valid(valid: Bool, +url: String, +seed: List<&2,U32>, port: U32) -> IO(Result<&1,&1,U32 & String,Relay.Bridge>):
  match valid:
    case False{}:
      IO.pure(Result<&1,&1,U32 & String,Relay.Bridge>,Fail{(1,"inbound relay requires a bound loopback port")})
    case True{}:
      do IO<Result<&1,&1,U32 & String,Relay.Bridge>>:
        relay : Result<&1,&1,U32 & String,Client.Connection> <- Client.connect(url,seed)
        start_connected(relay,port,url,seed)

def start(url: String, seed: List<&2,U32>, +local_port: U32) -> IO(Result<&1,&1,U32 & String,Relay.Bridge>):
  start_valid(U32.is_gt(local_port,0) && U32.is_le(local_port,65535),url,seed,local_port)
