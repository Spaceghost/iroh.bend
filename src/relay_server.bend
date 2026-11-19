import Base
import ./relay_server_socket.bend as Net
import ./relay_auth.bend as Auth
import ./relay_exporter.bend as Exporter
import ./handshake.bend as Handshake
import ./relay.bend as Wire
import ./relay_heartbeat.bend as Health
import ./relay_access.bend as Access

type Client is Data:
  Challenged{id: U32, version: Wire.Version, nonce: List<&2,U32>}
  Authorized{id: U32, version: Wire.Version, key: List<&2,U32>, heartbeat: Health.Heartbeat}

# Delivery history belongs to the endpoint and survives session promotion.
type Deliveries is Data:
  Delivered{sender: List<&2,U32>, recipients: List<&2,List<&2,U32>>}

type Clients is Data:
  Registry{sessions: List<&2,Client>, deliveries: List<&2,Deliveries>}

type State is Type:
  Serving{socket: Net.ServerSocket, clients: Clients}
  AwaitingAccess{socket: Net.ServerSocket, clients: Clients, id: U32, protocol: Wire.Version, key: List<&2,U32>}
  Ended{state: State, id: U32, key: List<&2,U32>}

type Server is Type:
  Relay{state: State, access: Access.Control}

def id_of(client: Client) -> U32:
  match client:
    case Challenged{id,_,_}:
      id
    case Authorized{id,_,_,_}:
      id

def bytes_equal(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(x,y) && bytes_equal(xs,ys)
    case _ _:
      False{}

def select(client: Client, rest: Maybe<&2,Client>, matches: Bool) -> Maybe<&2,Client>:
  match matches:
    case True{}:
      Some{client}
    case False{}:
      rest

def by_id(clients: List<&2,Client>, +id: U32) -> Maybe<&2,Client>:
  match clients:
    case Nil{}:
      None{}
    case Con{+client,rest}:
      select(client,by_id(rest,id),U32.is_eq(id_of(client),id))

def by_key(clients: List<&2,Client>, +key: List<&2,U32>) -> Maybe<&2,Client>:
  match clients:
    case Nil{}:
      None{}
    case Con{Authorized{+id,+version,+public,heartbeat},rest}:
      select(Authorized{id,version,public,heartbeat},by_key(rest,key),bytes_equal(key,public))
    case Con{_,rest}:
      by_key(rest,key)

def filter(client: Client, rest: List<&2,Client>, remove: Bool) -> List<&2,Client>:
  match remove:
    case True{}:
      rest
    case False{}:
      Con{client,rest}

def without(clients: List<&2,Client>, +id: U32) -> List<&2,Client>:
  match clients:
    case Nil{}:
      []
    case Con{+client,rest}:
      filter(client,without(rest,id),U32.is_eq(id_of(client),id))

def find_id(clients: Clients, id: U32) -> Maybe<&2,Client>:
  Registry{sessions,_} = clients
  by_id(sessions,id)

def find_key(clients: Clients, key: List<&2,U32>) -> Maybe<&2,Client>:
  Registry{sessions,_} = clients
  by_key(sessions,key)

def add_client(clients: Clients, client: Client) -> Clients:
  Registry{sessions,deliveries} = clients
  Registry{Con{client,sessions},deliveries}

def drop_client(clients: Clients, id: U32) -> Clients:
  Registry{sessions,deliveries} = clients
  Registry{without(sessions,id),deliveries}

def replace_session(replacement: List<&2,Client>, remainder: Unit -> List<&2,Client>, matched: Bool)
    -> List<&2,Client>:
  match matched:
    case True{}:
      replacement
    case False{}:
      remainder(Unit{})

def replace_at(sessions: List<&2,Client>, +id: U32, +client: Client) -> List<&2,Client>:
  match sessions:
    case Nil{}:
      []
    case Con{+head,+rest}:
      replace_session(Con{client,rest},_ => Con{head,replace_at(rest,id,client)},U32.is_eq(id,id_of(head)))

def update_client(clients: Clients, +client: Client) -> Clients:
  Registry{sessions,deliveries} = clients
  Registry{replace_at(sessions,id_of(client),client),deliveries}

def contains_key(keys: List<&2,List<&2,U32>>, +wanted: List<&2,U32>) -> Bool:
  match keys:
    case Nil{}:
      False{}
    case Con{key,rest}:
      bytes_equal(key,wanted) || contains_key(rest,wanted)

def insert_key(keys: List<&2,List<&2,U32>>, key: List<&2,U32>, present: Bool) -> List<&2,List<&2,U32>>:
  match present:
    case True{}:
      keys
    case False{}:
      Con{key,keys}

def update_delivery(replaced: Unit -> List<&2,Deliveries>, rest: Unit -> List<&2,Deliveries>,
    matched: Bool) -> List<&2,Deliveries>:
  match matched:
    case True{}:
      replaced(Unit{})
    case False{}:
      rest(Unit{})

def add_delivery(deliveries: List<&2,Deliveries>, +sender: List<&2,U32>, +recipient: List<&2,U32>)
    -> List<&2,Deliveries>:
  match deliveries:
    case Nil{}:
      [Delivered{sender,[recipient]}]
    case Con{Delivered{+key,+peers},+rest}:
      update_delivery(_ => Con{Delivered{key,insert_key(peers,recipient,contains_key(peers,recipient))},rest},
        _ => Con{Delivered{key,peers},add_delivery(rest,sender,recipient)},bytes_equal(key,sender))

def extract_delivery(found: List<&2,Deliveries> & List<&2,List<&2,U32>>,
    rest: Unit -> (List<&2,Deliveries> & List<&2,List<&2,U32>>), matched: Bool)
    -> List<&2,Deliveries> & List<&2,List<&2,U32>>:
  match matched:
    case True{}:
      found
    case False{}:
      rest(Unit{})

def restore_delivery(original: Deliveries, rest: List<&2,Deliveries> & List<&2,List<&2,U32>>)
    -> List<&2,Deliveries> & List<&2,List<&2,U32>>:
  (next,recipients) = rest
  (Con{original,next},recipients)

def take_delivery(deliveries: List<&2,Deliveries>, +sender: List<&2,U32>)
    -> List<&2,Deliveries> & List<&2,List<&2,U32>>:
  match deliveries:
    case Nil{}:
      ([],[])
    case Con{Delivered{+key,+peers},+rest}:
      extract_delivery((rest,peers),_ => restore_delivery(Delivered{key,peers},take_delivery(rest,sender)),
        bytes_equal(key,sender))

def version(number: U32) -> Wire.Version:
  match number:
    case 1:
      Wire.V1{}
    case _:
      Wire.V2{}

def capture_requests(socket: Net.ServerSocket, port: U32, access: Access.Control)
    -> IO(Result<&1,&1,U32 & String,Server & U32>):
  match access:
    case Access.AllowAll{}:
      IO.pure(Result<&1,&1,U32 & String,Server & U32>,
        Done{(Relay{Serving{socket,Registry{[],[]}},Access.AllowAll{}},port)})
    case _:
      do IO<Result<&1,&1,U32 & String,Server & U32>>:
        enabled : Net.ServerSocket <- Net.relay_enable_request_details(socket)
        return Done{(Relay{Serving{enabled,Registry{[],[]}},access},port)}

def attached(result: Result<&1,&1,U32 & String,Net.ServerSocket & U32>, access: Access.Control)
    -> IO(Result<&1,&1,U32 & String,Server & U32>):
  match result:
    case Done{(socket,port)}:
      capture_requests(socket,port,access)
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Server & U32>,Fail{error})

def bind_with_access(host: String, port: U32, cert: String, key: String, access: Access.Control)
    -> IO(Result<&1,&1,U32 & String,Server & U32>):
  do IO<Result<&1,&1,U32 & String,Server & U32>>:
    result : Result<&1,&1,U32 & String,Net.ServerSocket & U32> <- Net.relay_bind(host,port,cert,key)
    attached(result,access)

def bind(host: String, port: U32, cert: String, key: String)
    -> IO(Result<&1,&1,U32 & String,Server & U32>):
  bind_with_access(host,port,cert,key,Access.AllowAll{})

def controller(reply: Access.Control & Access.Decision) -> Access.Control:
  (next,_) = reply
  next

def disconnect_all(sessions: List<&2,Client>, access: Access.Control) -> IO(Unit):
  match sessions:
    case Nil{}:
      IO.pure(Unit,Unit{})
    case Con{Authorized{id,_,key,_},rest}:
      do IO<Unit>:
        reply : Access.Control & Access.Decision <- Access.process(access,Access.Disconnected{id,key})
        disconnect_all(rest,controller(reply))
    case Con{_,rest}:
      disconnect_all(rest,access)

def stop_state(state: State, access: Access.Control) -> IO(Unit):
  match state:
    case Serving{socket,Registry{sessions,_}}:
      do IO<Unit>:
        Net.relay_stop(socket)
        disconnect_all(sessions,access)
    case AwaitingAccess{socket,Registry{sessions,_},_,_,_}:
      do IO<Unit>:
        Net.relay_stop(socket)
        disconnect_all(sessions,access)
    case Ended{next,id,key}:
      do IO<Unit>:
        reply : Access.Control & Access.Decision <- Access.process(access,Access.Disconnected{id,key})
        stop_state(next,controller(reply))

def stop(server: Server) -> IO(Unit):
  Relay{state,access} = server
  stop_state(state,access)

def queue_auth(socket: Net.ServerSocket, id: U32, wire: Handshake.Encoding)
    -> IO(Net.ServerSocket & Bool):
  match wire:
    case Handshake.Encoded{bytes}:
      Net.relay_queue(socket,id,bytes)
    case Handshake.InvalidEncoding{}:
      IO.pure(Net.ServerSocket & Bool,(socket,False{}))

def queue_frame(socket: Net.ServerSocket, id: U32, wire: Wire.Encoding) -> IO(Net.ServerSocket & Bool):
  match wire:
    case Wire.Encoded{bytes}:
      Net.relay_queue(socket,id,bytes)
    case Wire.Rejected{_}:
      IO.pure(Net.ServerSocket & Bool,(socket,False{}))

def notify(socket: Net.ServerSocket, id: U32, protocol: Wire.Version, tag: U32, bytes: List<&2,U32>)
    -> IO(Net.ServerSocket):
  do IO<Net.ServerSocket>:
    queued : Net.ServerSocket & Bool <- queue_frame(socket,id,Wire.encode(Wire.ToClient{},protocol,tag,bytes))
    return Pair.fst(Net.ServerSocket,Bool,queued)

def notify_recipient(socket: Net.ServerSocket, client: Maybe<&2,Client>, sender: List<&2,U32>)
    -> IO(Net.ServerSocket):
  match client:
    case Some{Authorized{id,protocol,_,_}}:
      notify(socket,id,protocol,8,sender)
    case _:
      IO.pure(Net.ServerSocket,socket)

def notify_departure(recipients: List<&2,List<&2,U32>>, socket: Net.ServerSocket,
    +sessions: List<&2,Client>, +sender: List<&2,U32>) -> IO(Net.ServerSocket):
  match recipients:
    case Nil{}:
      IO.pure(Net.ServerSocket,socket)
    case Con{key,rest}:
      do IO<Net.ServerSocket>:
        next : Net.ServerSocket <- notify_recipient(socket,by_key(sessions,key),sender)
        notify_departure(rest,next,sessions,sender)

def status_text(chars: List<&2,Char>) -> List<&2,U32>:
  match chars:
    case Nil{}:
      []
    case Con{c,rest}:
      Con{Char.to_u32(c),status_text(rest)}

def status(socket: Net.ServerSocket, client: Maybe<&2,Client>, +code: U32, text: String)
    -> IO(Net.ServerSocket):
  match client:
    case Some{Authorized{id,Wire.V1{},_,_}}:
      notify(socket,id,Wire.V1{},11,status_text(String.to_list(text)))
    case Some{Authorized{id,Wire.V2{},_,_}}:
      notify(socket,id,Wire.V2{},13,[code])
    case _:
      IO.pure(Net.ServerSocket,socket)

def process_departure(socket: Net.ServerSocket, +sessions: List<&2,Client>, sender: List<&2,U32>,
    delivery: List<&2,Deliveries> & List<&2,List<&2,U32>>) -> IO(State):
  (remaining,recipients) = delivery
  do IO<State>:
    next : Net.ServerSocket <- notify_departure(recipients,socket,sessions,sender)
    return Serving{next,Registry{sessions,remaining}}

def last_departure(socket: Net.ServerSocket, clients: Clients, +sender: List<&2,U32>) -> IO(State):
  Registry{sessions,deliveries} = clients
  process_departure(socket,sessions,sender,take_delivery(deliveries,sender))

def promote_or_depart(socket: Net.ServerSocket, clients: Clients, sender: List<&2,U32>,
    +replacement: Maybe<&2,Client>) -> IO(State):
  match replacement:
    case Some{_}:
      do IO<State>:
        next : Net.ServerSocket <- status(socket,replacement,0,
          "The connection is healthy and has recovered from previous problems")
        return Serving{next,clients}
    case None{}:
      last_departure(socket,clients,sender)

def remove_active(socket: Net.ServerSocket, +clients: Clients, +sender: List<&2,U32>, active: Bool)
    -> IO(State):
  match active:
    case True{}:
      promote_or_depart(socket,clients,sender,find_key(clients,sender))
    case False{}:
      IO.pure(State,Serving{socket,clients})

def currently_active(previous: Maybe<&2,Client>, id: U32) -> Bool:
  match previous:
    case Some{Authorized{active,_,_,_}}:
      U32.is_eq(active,id)
    case _:
      False{}

def unregister(socket: Net.ServerSocket, +clients: Clients, +id: U32, gone: Maybe<&2,Client>) -> IO(State):
  match gone:
    case Some{Authorized{_,_,+key,_}}:
      do IO<State>:
        next : State <- remove_active(socket,drop_client(clients,id),key,currently_active(find_key(clients,key),id))
        return Ended{next,id,key}
    case _:
      IO.pure(State,Serving{socket,drop_client(clients,id)})

def kick(socket: Net.ServerSocket, +id: U32, flush: U32, +clients: Clients) -> IO(State):
  do IO<State>:
    next : Net.ServerSocket <- Net.relay_kick(socket,id,flush)
    unregister(next,clients,id,find_id(clients,id))

def registered(result: Net.ServerSocket & Bool, clients: Clients, +id: U32,
    protocol: Wire.Version, nonce: List<&2,U32>) -> IO(State):
  match result:
    case (socket,True{}):
      IO.pure(State,Serving{socket,add_client(clients,Challenged{id,protocol,nonce})})
    case (socket,False{}):
      kick(socket,id,0,clients)

def begin_claim(result: Result<&1,&1,U32 & String,List<&2,U32>>, socket: Net.ServerSocket,
    clients: Clients, +id: U32, protocol: Wire.Version) -> IO(State):
  match result:
    case Done{+nonce}:
      do IO<State>:
        queued : Net.ServerSocket & Bool <- queue_auth(socket,id,Handshake.encode(Handshake.Challenge{nonce}))
        registered(queued,clients,id,protocol,nonce)
    case Fail{_}:
      kick(socket,id,0,clients)

def after_send(queued: Net.ServerSocket & Bool, clients: Clients) -> State:
  (socket,_) = queued
  Serving{socket,clients}

def send_frame(socket: Net.ServerSocket, clients: Clients, id: U32, wire: Wire.Encoding) -> IO(State):
  do IO<State>:
    queued : Net.ServerSocket & Bool <- queue_frame(socket,id,wire)
    return after_send(queued,clients)

def confirmed(queued: Net.ServerSocket & Bool, clients: Clients, +id: U32,
    protocol: Wire.Version, +key: List<&2,U32>, +previous: Maybe<&2,Client>) -> IO(State):
  match queued:
    case (socket,True{}):
      do IO<State>:
        marked : Net.ServerSocket <- Net.relay_authorized(socket,id)
        next : Net.ServerSocket <- status(marked,previous,1,
          "Another endpoint connected with the same endpoint id. No more messages will be received.")
        random : Result<&1,&1,U32 & String,U32> <- IO.random_u32()
        now : U32 <- Net.relay_millis()
        return Serving{next,add_client(drop_client(clients,id),Authorized{id,protocol,key,
          Health.initial(now,Result.default(&1,&1,U32 & String,U32,random,id))})}
    case (socket,False{}):
      do IO<State>:
        next : State <- kick(socket,id,0,clients)
        return Ended{next,id,key}

def deny_after_send(queued: Net.ServerSocket & Bool, id: U32, clients: Clients) -> IO(State):
  (socket,_) = queued
  kick(socket,id,1,clients)

def confirm(socket: Net.ServerSocket, +clients: Clients, +id: U32, protocol: Wire.Version,
    +key: List<&2,U32>) -> IO(State):
  do IO<State>:
    queued : Net.ServerSocket & Bool <- queue_auth(socket,id,Handshake.encode(Handshake.Confirmed{}))
    confirmed(queued,clients,id,protocol,key,find_key(clients,key))

def challenge(socket: Net.ServerSocket, clients: Clients, id: U32, protocol: Wire.Version) -> IO(State):
  do IO<State>:
    nonce : Result<&1,&1,U32 & String,List<&2,U32>> <- Net.relay_nonce()
    begin_claim(nonce,socket,clients,id,protocol)

def export_verified(valid: Bool, socket: Net.ServerSocket, clients: Clients, id: U32,
    protocol: Wire.Version, key: List<&2,U32>) -> IO(State):
  match valid:
    case True{}:
      IO.pure(State,AwaitingAccess{socket,clients,id,protocol,key})
    case False{}:
      challenge(socket,clients,id,protocol)

def export_proof(exported: Net.ServerSocket & Maybe<&1,List<&2,U32>>, clients: Clients,
    id: U32, protocol: Wire.Version, +key: List<&2,U32>,
    signature: List<&2,U32>, suffix: List<&2,U32>) -> IO(State):
  match exported:
    case (socket,Some{material}):
      do IO<State>:
        valid : Bool <- Exporter.verify(key,signature,suffix,material)
        export_verified(valid,socket,clients,id,protocol,key)
    case (socket,None{}):
      challenge(socket,clients,id,protocol)

def check_exporter(proof: Exporter.Proof, socket: Net.ServerSocket, clients: Clients,
    +id: U32, protocol: Wire.Version) -> IO(State):
  match proof:
    case Exporter.ExporterProof{+key,signature,suffix}:
      do IO<State>:
        exported : Net.ServerSocket & Maybe<&1,List<&2,U32>> <- Net.relay_export_keying_material(socket,id,key)
        export_proof(exported,clients,id,protocol,key,signature,suffix)
    case Exporter.MalformedExporterProof{}:
      kick(socket,id,0,clients)

def client_header(header: Net.ServerSocket & Maybe<&1,List<&2,U32>>, clients: Clients,
    id: U32, protocol: Wire.Version) -> IO(State):
  match header:
    case (socket,Some{bytes}):
      check_exporter(Exporter.decode(bytes),socket,clients,id,protocol)
    case (socket,None{}):
      challenge(socket,clients,id,protocol)

def authenticated(valid: Bool, socket: Net.ServerSocket, clients: Clients,
    +id: U32, protocol: Wire.Version, key: List<&2,U32>) -> IO(State):
  match valid:
    case True{}:
      IO.pure(State,AwaitingAccess{socket,clients,id,protocol,key})
    case False{}:
      do IO<State>:
        queued : Net.ServerSocket & Bool <- queue_auth(socket,id,
          Handshake.encode(Handshake.Denied{[115,105,103,110,97,116,117,114,101,32,105,110,118,97,108,105,100]}))
        deny_after_send(queued,id,clients)

def verify(socket: Net.ServerSocket, clients: Clients, id: U32, protocol: Wire.Version,
    proof: Handshake.Auth, nonce: List<&2,U32>) -> IO(State):
  match proof:
    case Handshake.ClientProof{+key,sig}:
      do IO<State>:
        ok : Bool <- Auth.verify_challenge(Handshake.ClientProof{key,sig},nonce)
        authenticated(ok,socket,clients,id,protocol,key)
    case _:
      kick(socket,id,0,clients)

def forwarded(queued: Net.ServerSocket & Bool, clients: Clients, sender: List<&2,U32>,
    receiver: List<&2,U32>) -> State:
  match queued:
    case (socket,True{}):
      Registry{sessions,deliveries} = clients
      Serving{socket,Registry{sessions,add_delivery(deliveries,sender,receiver)}}
    case (socket,False{}):
      Serving{socket,clients}

def forward(socket: Net.ServerSocket, clients: Clients, destination: Maybe<&2,Client>,
    +sender: List<&2,U32>, ecn: U32, segment: U32, data: List<&2,U32>) -> IO(State):
  match destination:
    case Some{Authorized{id,version,key,_}}:
      do IO<State>:
        queued : Net.ServerSocket & Bool <- queue_frame(socket,id,
          Wire.encode_datagram(Wire.ToClient{},version,sender,ecn,segment,data))
        return forwarded(queued,clients,sender,key)
    case _:
      IO.pure(State,Serving{socket,clients})

def route(socket: Net.ServerSocket, +clients: Clients, source: List<&2,U32>, packet: Wire.Packet) -> IO(State):
  match packet:
    case Wire.Datagram{dest,ecn,segment,bytes}:
      forward(socket,clients,find_key(clients,dest),source,ecn,segment,bytes)
    case _:
      IO.pure(State,Serving{socket,clients})

def relay_frame(socket: Net.ServerSocket, clients: Clients, id: U32,
    protocol: Wire.Version, sender: List<&2,U32>, frame: Wire.Frame) -> IO(State):
  match frame:
    case Wire.Message{9,ping}:
      send_frame(socket,clients,id,Wire.encode(Wire.ToClient{},protocol,10,ping))
    case Wire.Message{10,_}:
      IO.pure(State,Serving{socket,clients})
    case Wire.Message{tag,bytes}:
      route(socket,clients,sender,Wire.packet(Wire.Message{tag,bytes}))
    case _:
      kick(socket,id,0,clients)

def received_activity(timer: Health.Heartbeat, now: U32, frame: Wire.Frame) -> Health.Heartbeat:
  match frame:
    case Wire.Message{10,pong}:
      Health.received_pong(timer,now,pong)
    case _:
      Health.touch(timer,now)

def authenticated_frame(socket: Net.ServerSocket, clients: Clients, +id: U32, +version: Wire.Version,
    +sender: List<&2,U32>, timer: Health.Heartbeat, now: U32, +frame: Wire.Frame) -> IO(State):
  updated = update_client(clients,Authorized{id,version,sender,received_activity(timer,now,frame)})
  relay_frame(socket,updated,id,version,sender,frame)

def handle_bytes(socket: Net.ServerSocket, clients: Clients, match_client: Maybe<&2,Client>,
    bytes: List<&2,U32>, now: U32) -> IO(State):
  match match_client:
    case Some{Challenged{id,version,nonce}}:
      verify(socket,clients,id,version,Handshake.decode(bytes),nonce)
    case Some{Authorized{id,+version,key,timer}}:
      authenticated_frame(socket,clients,id,version,key,timer,now,Wire.decode(Wire.ToRelay{},version,bytes))
    case None{}:
      IO.pure(State,Serving{socket,clients})

def event(socket: Net.ServerSocket, +clients: Clients, update: Net.SocketEvent, now: U32) -> IO(State):
  match update:
    case Net.RelayIdle{}:
      IO.pure(State,Serving{socket,clients})
    case Net.RelayJoined{+id,number}:
      do IO<State>:
        header : Net.ServerSocket & Maybe<&1,List<&2,U32>> <- Net.relay_client_auth_header(socket,id)
        client_header(header,clients,id,version(number))
    case Net.RelayBytes{+id,bytes}:
      handle_bytes(socket,clients,find_id(clients,id),bytes,now)
    case Net.RelayLeft{+id}:
      unregister(socket,clients,id,find_id(clients,id))

def step_event(result: Net.ServerSocket & Net.SocketEvent, clients: Clients, now: U32) -> IO(State):
  (socket,update) = result
  event(socket,clients,update,now)

type Due is Data:
  NoDeadline{}
  MissedPong{id: U32}
  NeedPing{id: U32, version: Wire.Version, key: List<&2,U32>, timer: Health.Heartbeat}

def deadline(action: Health.Action, id: U32, version: Wire.Version, key: List<&2,U32>,
    timer: Health.Heartbeat, rest: Unit -> Due) -> Due:
  match action:
    case Health.WaitForTraffic{}:
      rest(Unit{})
    case Health.ClosePeer{}:
      MissedPong{id}
    case Health.SendProbe{}:
      NeedPing{id,version,key,timer}

def due(sessions: List<&2,Client>, +now: U32) -> Due:
  match sessions:
    case Nil{}:
      NoDeadline{}
    case Con{Authorized{id,version,key,+timer},rest}:
      deadline(Health.action(timer,now),id,version,key,timer,_ => due(rest,now))
    case Con{_,rest}:
      due(rest,now)

def ping_queued(queued: Net.ServerSocket & Bool, clients: Clients, +id: U32, version: Wire.Version,
    key: List<&2,U32>, next: Health.Heartbeat) -> IO(State):
  match queued:
    case (socket,True{}):
      IO.pure(State,Serving{socket,update_client(clients,Authorized{id,version,key,next})})
    case (socket,False{}):
      kick(socket,id,0,clients)

def ping_bytes(socket: Net.ServerSocket, clients: Clients, +id: U32, +protocol: Wire.Version,
    key: List<&2,U32>, timer: Health.Heartbeat, now: U32, random: U32, parts: Wire.Split) -> IO(State):
  match parts:
    case Wire.Prefix{+nonce,_}:
      do IO<State>:
        queued : Net.ServerSocket & Bool <- queue_frame(socket,id,Wire.encode(Wire.ToClient{},protocol,9,nonce))
        ping_queued(queued,clients,id,protocol,key,Health.start(timer,now,random,nonce))
    case _:
      kick(socket,id,0,clients)

def emit_ping(socket: Net.ServerSocket, clients: Clients, +id: U32, protocol: Wire.Version,
    key: List<&2,U32>, timer: Health.Heartbeat, now: U32,
    random: Result<&1,&1,U32 & String,List<&2,U32>>) -> IO(State):
  match random:
    case Done{bytes}:
      do IO<State>:
        jitter : Result<&1,&1,U32 & String,U32> <- IO.random_u32()
        ping_bytes(socket,clients,id,protocol,key,timer,now,Result.default(&1,&1,U32 & String,U32,jitter,id),
          Wire.split_peer(8n,bytes,[]))
    case Fail{_}:
      kick(socket,id,0,clients)

def timers(socket: Net.ServerSocket, clients: Clients, now: U32, action: Due) -> IO(State):
  match action:
    case NoDeadline{}:
      IO.pure(State,Serving{socket,clients})
    case MissedPong{id}:
      kick(socket,id,0,clients)
    case NeedPing{id,protocol,key,timer}:
      do IO<State>:
        nonce : Result<&1,&1,U32 & String,List<&2,U32>> <- Net.relay_nonce()
        emit_ping(socket,clients,id,protocol,key,timer,now,nonce)

def check_timers(state: State, +now: U32) -> IO(State):
  match state:
    case Serving{socket,+clients}:
      Registry{sessions,_} = clients
      timers(socket,clients,now,due(sessions,now))
    case _:
      IO.pure(State,state)

def finish_state(state: State, access: Access.Control) -> IO(Server):
  match state:
    case Ended{next,id,key}:
      do IO<Server>:
        closed : Access.Control & Access.Decision <- Access.process(access,Access.Disconnected{id,key})
        finish_state(next,controller(closed))
    case _:
      IO.pure(Server,Relay{state,access})

def policy_denial(socket: Net.ServerSocket, clients: Clients, +id: U32, reason: Handshake.Encoding) -> IO(State):
  match reason:
    case Handshake.Encoded{bytes}:
      do IO<State>:
        queued : Net.ServerSocket & Bool <- Net.relay_queue(socket,id,bytes)
        deny_after_send(queued,id,clients)
    case Handshake.InvalidEncoding{}:
      do IO<State>:
        queued : Net.ServerSocket & Bool <- queue_auth(socket,id,
          Handshake.encode(Handshake.Denied{status_text(String.to_list("not authorized"))}))
        deny_after_send(queued,id,clients)

def decided(socket: Net.ServerSocket, clients: Clients, id: U32, protocol: Wire.Version,
    key: List<&2,U32>, decision: Access.Control & Access.Decision) -> IO(Server):
  match decision:
    case (access,Access.Allow{}):
      do IO<Server>:
        next : State <- confirm(socket,clients,id,protocol,key)
        finish_state(next,access)
    case (access,Access.Deny{Some{reason}}):
      do IO<Server>:
        next : State <- policy_denial(socket,clients,id,Handshake.encode(Handshake.Denied{reason}))
        return Relay{next,access}
    case (access,Access.Deny{None{}}):
      do IO<Server>:
        next : State <- policy_denial(socket,clients,id,Handshake.InvalidEncoding{})
        return Relay{next,access}

def authorize_request(details: Net.ServerSocket & Net.RequestDetails, clients: Clients, +id: U32,
    +protocol: Wire.Version, +key: List<&2,U32>, access: Access.Control) -> IO(Server):
  match details:
    case (socket,Net.MissingDetails{}):
      decided(socket,clients,id,protocol,key,(access,Access.Deny{None{}}))
    case (socket,Net.Details{path,fields}):
      do IO<Server>:
        reply : Access.Control & Access.Decision <- Access.process(access,
          Access.Admission{Access.Connecting{id,key,protocol,Net.Details{path,fields}}})
        decided(socket,clients,id,protocol,key,reply)

def authorize(socket: Net.ServerSocket, clients: Clients, +id: U32,
    protocol: Wire.Version, key: List<&2,U32>, access: Access.Control) -> IO(Server):
  match access:
    case Access.AllowAll{}:
      decided(socket,clients,id,protocol,key,(Access.AllowAll{},Access.Allow{}))
    case _:
      do IO<Server>:
        details : Net.ServerSocket & Net.RequestDetails <- Net.relay_request_details(socket,id)
        authorize_request(details,clients,id,protocol,key,access)

def settle(state: State, access: Access.Control) -> IO(Server):
  match state:
    case AwaitingAccess{socket,clients,id,protocol,key}:
      authorize(socket,clients,id,protocol,key,access)
    case _:
      finish_state(state,access)

def step_timers(server: Server, now: U32) -> IO(Server):
  Relay{state,access} = server
  do IO<Server>:
    next : State <- check_timers(state,now)
    finish_state(next,access)

def timed_event(result: Net.ServerSocket & Net.SocketEvent, clients: Clients, access: Access.Control,
    +now: U32) -> IO(Server):
  do IO<Server>:
    updated : State <- step_event(result,clients,now)
    settled : Server <- settle(updated,access)
    step_timers(settled,now)

def step_state(state: State, access: Access.Control) -> IO(Server):
  match state:
    case Serving{socket,clients}:
      do IO<Server>:
        result : Net.ServerSocket & Net.SocketEvent <- Net.relay_poll(socket)
        now : U32 <- Net.relay_millis()
        timed_event(result,clients,access,now)
    case _:
      settle(state,access)

# Advance the relay once. Call regularly from the application's event loop.
def step(server: Server) -> IO(Server):
  Relay{state,access} = server
  step_state(state,access)
