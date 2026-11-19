import Base
import ./relay_server_socket.bend as Net
import ./relay_auth.bend as Auth
import ./relay_exporter.bend as Exporter
import ./handshake.bend as Handshake
import ./relay.bend as Wire

type Client is Data:
  Challenged{id: U32, version: Wire.Version, nonce: List<&2,U32>}
  Authorized{id: U32, version: Wire.Version, key: List<&2,U32>}

type Server is Type:
  Serving{socket: Net.ServerSocket, clients: List<&2,Client>}

def id_of(client: Client) -> U32:
  match client:
    case Challenged{id,_,_}:
      id
    case Authorized{id,_,_}:
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
    case Con{Authorized{+id,+version,+public},rest}:
      select(Authorized{id,version,public},by_key(rest,key),bytes_equal(key,public))
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

def version(number: U32) -> Wire.Version:
  match number:
    case 1:
      Wire.V1{}
    case _:
      Wire.V2{}

def attached(result: Result<&1,&1,U32 & String, Net.ServerSocket & U32>)
    -> Result<&1,&1,U32 & String, Server & U32>:
  match result:
    case Done{(socket,port)}:
      Done{(Serving{socket,[]},port)}
    case Fail{error}:
      Fail{error}

def bind(host: String, port: U32, cert: String, key: String)
    -> IO(Result<&1,&1,U32 & String, Server & U32>):
  do IO<Result<&1,&1,U32 & String, Server & U32>>:
    result : Result<&1,&1,U32 & String, Net.ServerSocket & U32> <- Net.relay_bind(host,port,cert,key)
    return attached(result)

def stop(server: Server) -> IO(Unit):
  Serving{socket,_} = server
  Net.relay_stop(socket)

def queue_auth(socket: Net.ServerSocket, id: U32, wire: Handshake.Encoding)
    -> IO(Net.ServerSocket & Bool):
  match wire:
    case Handshake.Encoded{bytes}:
      Net.relay_queue(socket,id,bytes)
    case Handshake.InvalidEncoding{}:
      IO.pure(Net.ServerSocket & Bool,(socket,False{}))

def kick(socket: Net.ServerSocket, +id: U32, flush: U32, clients: List<&2,Client>) -> IO(Server):
  do IO<Server>:
    next : Net.ServerSocket <- Net.relay_kick(socket,id,flush)
    return Serving{next,without(clients,id)}

def registered(result: Net.ServerSocket & Bool, clients: List<&2,Client>, +id: U32,
    protocol: Wire.Version, nonce: List<&2,U32>) -> IO(Server):
  match result:
    case (socket,True{}):
      IO.pure(Server,Serving{socket,Con{Challenged{id,protocol,nonce},clients}})
    case (socket,False{}):
      kick(socket,id,0,clients)

def begin_claim(result: Result<&1,&1,U32 & String,List<&2,U32>>, socket: Net.ServerSocket,
    clients: List<&2,Client>, +id: U32, protocol: Wire.Version) -> IO(Server):
  match result:
    case Done{+nonce}:
      do IO<Server>:
        queued : Net.ServerSocket & Bool <- queue_auth(socket,id,Handshake.encode(Handshake.Challenge{nonce}))
        registered(queued,clients,id,protocol,nonce)
    case Fail{_}:
      kick(socket,id,0,clients)

def after_send(queued: Net.ServerSocket & Bool, clients: List<&2,Client>) -> Server:
  (socket,_) = queued
  Serving{socket,clients}

def send_frame(socket: Net.ServerSocket, clients: List<&2,Client>, id: U32, wire: Wire.Encoding) -> IO(Server):
  match wire:
    case Wire.Encoded{bytes}:
      do IO<Server>:
        queued : Net.ServerSocket & Bool <- Net.relay_queue(socket,id,bytes)
        return after_send(queued,clients)
    case Wire.Rejected{_}:
      IO.pure(Server,Serving{socket,clients})

def finish_replaced(queued: Net.ServerSocket & Bool, id: U32) -> IO(Net.ServerSocket):
  (socket,_) = queued
  Net.relay_kick(socket,id,1)

def replace_peer(socket: Net.ServerSocket, previous: Maybe<&2,Client>) -> IO(Net.ServerSocket):
  match previous:
    case Some{Authorized{+id,Wire.V2{},_}}:
      do IO<Net.ServerSocket>:
        queued : Net.ServerSocket & Bool <- Net.relay_queue(socket,id,[13,1])
        finish_replaced(queued,id)
    case Some{Authorized{id,Wire.V1{},_}}:
      Net.relay_kick(socket,id,0)
    case _:
      IO.pure(Net.ServerSocket,socket)

def remove_previous(previous: Maybe<&2,Client>, clients: List<&2,Client>) -> List<&2,Client>:
  match previous:
    case Some{client}:
      without(clients,id_of(client))
    case None{}:
      clients

def confirmed(queued: Net.ServerSocket & Bool, clients: List<&2,Client>, +id: U32,
    protocol: Wire.Version, key: List<&2,U32>, +previous: Maybe<&2,Client>) -> IO(Server):
  match queued:
    case (socket,True{}):
      do IO<Server>:
        marked : Net.ServerSocket <- Net.relay_authorized(socket,id)
        next : Net.ServerSocket <- replace_peer(marked,previous)
        return Serving{next,Con{Authorized{id,protocol,key},remove_previous(previous,without(clients,id))}}
    case (socket,False{}):
      kick(socket,id,0,clients)

def deny_after_send(queued: Net.ServerSocket & Bool, id: U32, clients: List<&2,Client>) -> IO(Server):
  (socket,_) = queued
  kick(socket,id,1,clients)

def confirm(socket: Net.ServerSocket, +clients: List<&2,Client>, +id: U32, protocol: Wire.Version,
    +key: List<&2,U32>) -> IO(Server):
  do IO<Server>:
    queued : Net.ServerSocket & Bool <- queue_auth(socket,id,Handshake.encode(Handshake.Confirmed{}))
    confirmed(queued,clients,id,protocol,key,by_key(clients,key))

def challenge(socket: Net.ServerSocket, clients: List<&2,Client>, id: U32, protocol: Wire.Version) -> IO(Server):
  do IO<Server>:
    nonce : Result<&1,&1,U32 & String,List<&2,U32>> <- Net.relay_nonce()
    begin_claim(nonce,socket,clients,id,protocol)

def export_verified(valid: Bool, socket: Net.ServerSocket, clients: List<&2,Client>, id: U32,
    protocol: Wire.Version, key: List<&2,U32>) -> IO(Server):
  match valid:
    case True{}:
      confirm(socket,clients,id,protocol,key)
    case False{}:
      challenge(socket,clients,id,protocol)

def export_proof(exported: Net.ServerSocket & Maybe<&1,List<&2,U32>>, clients: List<&2,Client>,
    id: U32, protocol: Wire.Version, +key: List<&2,U32>,
    signature: List<&2,U32>, suffix: List<&2,U32>) -> IO(Server):
  match exported:
    case (socket,Some{material}):
      do IO<Server>:
        valid : Bool <- Exporter.verify(key,signature,suffix,material)
        export_verified(valid,socket,clients,id,protocol,key)
    case (socket,None{}):
      challenge(socket,clients,id,protocol)

def check_exporter(proof: Exporter.Proof, socket: Net.ServerSocket, clients: List<&2,Client>,
    +id: U32, protocol: Wire.Version) -> IO(Server):
  match proof:
    case Exporter.ExporterProof{+key,signature,suffix}:
      do IO<Server>:
        exported : Net.ServerSocket & Maybe<&1,List<&2,U32>> <- Net.relay_export_keying_material(socket,id,key)
        export_proof(exported,clients,id,protocol,key,signature,suffix)
    case Exporter.MalformedExporterProof{}:
      kick(socket,id,0,clients)

def client_header(header: Net.ServerSocket & Maybe<&1,List<&2,U32>>, clients: List<&2,Client>,
    id: U32, protocol: Wire.Version) -> IO(Server):
  match header:
    case (socket,Some{bytes}):
      check_exporter(Exporter.decode(bytes),socket,clients,id,protocol)
    case (socket,None{}):
      challenge(socket,clients,id,protocol)

def authenticated(valid: Bool, socket: Net.ServerSocket, clients: List<&2,Client>,
    +id: U32, protocol: Wire.Version, key: List<&2,U32>) -> IO(Server):
  match valid:
    case True{}:
      confirm(socket,clients,id,protocol,key)
    case False{}:
      do IO<Server>:
        queued : Net.ServerSocket & Bool <- queue_auth(socket,id,
          Handshake.encode(Handshake.Denied{[115,105,103,110,97,116,117,114,101,32,105,110,118,97,108,105,100]}))
        deny_after_send(queued,id,clients)

def verify(socket: Net.ServerSocket, clients: List<&2,Client>, id: U32, protocol: Wire.Version,
    proof: Handshake.Auth, nonce: List<&2,U32>) -> IO(Server):
  match proof:
    case Handshake.ClientProof{+key,sig}:
      do IO<Server>:
        ok : Bool <- Auth.verify_challenge(Handshake.ClientProof{key,sig},nonce)
        authenticated(ok,socket,clients,id,protocol,key)
    case _:
      kick(socket,id,0,clients)

def forward(socket: Net.ServerSocket, clients: List<&2,Client>, destination: Maybe<&2,Client>,
    sender: List<&2,U32>, ecn: U32, segment: U32, data: List<&2,U32>) -> IO(Server):
  match destination:
    case Some{Authorized{id,version,_}}:
      send_frame(socket,clients,id,Wire.encode_datagram(Wire.ToClient{},version,sender,ecn,segment,data))
    case _:
      IO.pure(Server,Serving{socket,clients})

def route(socket: Net.ServerSocket, +clients: List<&2,Client>, source: List<&2,U32>, packet: Wire.Packet) -> IO(Server):
  match packet:
    case Wire.Datagram{dest,ecn,segment,bytes}:
      forward(socket,clients,by_key(clients,dest),source,ecn,segment,bytes)
    case _:
      IO.pure(Server,Serving{socket,clients})

def relay_frame(socket: Net.ServerSocket, clients: List<&2,Client>, id: U32,
    protocol: Wire.Version, sender: List<&2,U32>, frame: Wire.Frame) -> IO(Server):
  match frame:
    case Wire.Message{9,ping}:
      send_frame(socket,clients,id,Wire.encode(Wire.ToClient{},protocol,10,ping))
    case Wire.Message{10,_}:
      IO.pure(Server,Serving{socket,clients})
    case Wire.Message{tag,bytes}:
      route(socket,clients,sender,Wire.packet(Wire.Message{tag,bytes}))
    case _:
      kick(socket,id,0,clients)

def handle_bytes(socket: Net.ServerSocket, clients: List<&2,Client>, match_client: Maybe<&2,Client>,
    bytes: List<&2,U32>) -> IO(Server):
  match match_client:
    case Some{Challenged{id,version,nonce}}:
      verify(socket,clients,id,version,Handshake.decode(bytes),nonce)
    case Some{Authorized{id,+version,key}}:
      relay_frame(socket,clients,id,version,key,Wire.decode(Wire.ToRelay{},version,bytes))
    case None{}:
      IO.pure(Server,Serving{socket,clients})

def event(socket: Net.ServerSocket, +clients: List<&2,Client>, update: Net.SocketEvent) -> IO(Server):
  match update:
    case Net.RelayIdle{}:
      IO.pure(Server,Serving{socket,clients})
    case Net.RelayJoined{+id,number}:
      do IO<Server>:
        header : Net.ServerSocket & Maybe<&1,List<&2,U32>> <- Net.relay_client_auth_header(socket,id)
        client_header(header,clients,id,version(number))
    case Net.RelayBytes{id,bytes}:
      handle_bytes(socket,clients,by_id(clients,id),bytes)
    case Net.RelayLeft{id}:
      IO.pure(Server,Serving{socket,without(clients,id)})

def step_event(result: Net.ServerSocket & Net.SocketEvent, clients: List<&2,Client>) -> IO(Server):
  (socket,update) = result
  event(socket,clients,update)

# Advance the relay once. Call regularly from the application's event loop.
def step(server: Server) -> IO(Server):
  Serving{socket,clients} = server
  do IO<Server>:
    result : Net.ServerSocket & Net.SocketEvent <- Net.relay_poll(socket)
    step_event(result,clients)
