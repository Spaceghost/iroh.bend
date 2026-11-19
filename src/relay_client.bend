import Base
import ./relay.bend as Wire
import ./handshake.bend as Handshake
import ./relay_auth.bend as Auth
import ./relay_exporter.bend as Exporter
import ./ed25519.bend as Ed
import ./relay_socket.bend as WS

type Connection is Type:
  Online{socket: WS.RelaySocket, protocol: Wire.Version}

def close(conn: Connection) -> IO(Unit):
  match conn:
    case Online{socket, _}:
      WS.close(socket)

def fail_open(socket: WS.RelaySocket, description: String) ->
    IO(Result<&1,&1,U32 & String, Connection>):
  do IO<Result<&1,&1,U32 & String, Connection>>:
    WS.close(socket)
    return Fail{(1, description)}

def confirmed(socket: WS.RelaySocket, protocol: Wire.Version, frame: Handshake.Auth) ->
    IO(Result<&1,&1,U32 & String, Connection>):
  match frame:
    case Handshake.Confirmed{}:
      IO.pure(Result<&1,&1,U32 & String, Connection>, Done{Online{socket, protocol}})
    case Handshake.Denied{_}:
      fail_open(socket, "relay denied endpoint authentication")
    case _:
      fail_open(socket, "expected relay authentication confirmation")

def read_confirmation(reply: Result<&1,&1,U32 & String, WS.RelaySocket & List<&2,U32>>,
    protocol: Wire.Version) -> IO(Result<&1,&1,U32 & String, Connection>):
  match reply:
    case Done{(socket, bytes)}:
      confirmed(socket, protocol, Handshake.decode(bytes))
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String, Connection>, Fail{error})

def await_confirmation(sent: Result<&1,&1,U32 & String, WS.RelaySocket>, protocol: Wire.Version) ->
    IO(Result<&1,&1,U32 & String, Connection>):
  match sent:
    case Done{socket}:
      do IO<Result<&1,&1,U32 & String, Connection>>:
        reply : Result<&1,&1,U32 & String, WS.RelaySocket & List<&2,U32>> <- WS.recv(socket)
        read_confirmation(reply, protocol)
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String, Connection>, Fail{error})

def send_signed(socket: WS.RelaySocket, protocol: Wire.Version, proof: Handshake.Encoding) ->
    IO(Result<&1,&1,U32 & String, Connection>):
  match proof:
    case Handshake.Encoded{bytes}:
      do IO<Result<&1,&1,U32 & String, Connection>>:
        sent : Result<&1,&1,U32 & String, WS.RelaySocket> <- WS.send(socket, bytes)
        await_confirmation(sent, protocol)
    case Handshake.InvalidEncoding{}:
      fail_open(socket, "cannot encode relay authentication proof")

def proof_ready(socket: WS.RelaySocket, protocol: Wire.Version,
    proof: Result<&1,&1,U32 & String, Handshake.Auth>) ->
    IO(Result<&1,&1,U32 & String, Connection>):
  match proof:
    case Done{frame}:
      send_signed(socket, protocol, Handshake.encode(frame))
    case Fail{(_,message)}:
      fail_open(socket, message)

def answer_challenge(socket: WS.RelaySocket, protocol: Wire.Version,
    seed: List<&2,U32>, frame: Handshake.Auth, offered: Bool) -> IO(Result<&1,&1,U32 & String, Connection>):
  match frame offered:
    case Handshake.Challenge{nonce} _:
      do IO<Result<&1,&1,U32 & String, Connection>>:
        proof : Result<&1,&1,U32 & String, Handshake.Auth> <- Auth.sign_challenge(seed, nonce)
        proof_ready(socket, protocol, proof)
    case Handshake.Confirmed{} True{}:
      IO.pure(Result<&1,&1,U32 & String,Connection>,Done{Online{socket,protocol}})
    case Handshake.Denied{_} _:
      fail_open(socket, "relay denied endpoint authentication")
    case _ _:
      fail_open(socket, "expected relay authentication challenge")

def authenticate(reply: Result<&1,&1,U32 & String, WS.RelaySocket & List<&2,U32>>,
    protocol: Wire.Version, seed: List<&2,U32>, offered: Bool) -> IO(Result<&1,&1,U32 & String, Connection>):
  match reply:
    case Done{(socket, frame)}:
      answer_challenge(socket, protocol, seed, Handshake.decode(frame), offered)
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String, Connection>, Fail{error})

def version(+number: U32) -> Wire.Version:
  match number:
    case 1:
      Wire.V1{}
    case _:
      Wire.V2{}

def upgraded(reply: Result<&1,&1,U32 & String, WS.RelaySocket & (U32 & Bool)>, seed: List<&2,U32>) ->
    IO(Result<&1,&1,U32 & String, Connection>):
  match reply:
    case Done{(socket, (number, offered))}:
      do IO<Result<&1,&1,U32 & String, Connection>>:
        challenge : Result<&1,&1,U32 & String, WS.RelaySocket & List<&2,U32>> <- WS.recv(socket)
        authenticate(challenge, version(number), seed, offered)
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String, Connection>, Fail{error})

def exporter_proof(material: Maybe<&1,List<&2,U32>>, seed: List<&2,U32>) -> IO(Maybe<&1,List<&2,U32>>):
  match material:
    case Some{bytes}:
      Exporter.sign(seed,bytes)
    case None{}:
      IO.pure(Maybe<&1,List<&2,U32>>,None{})

def prepared(reply: Result<&1,&1,U32 & String,WS.PendingUpgrade & Maybe<&1,List<&2,U32>>>,
    +seed: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,Connection>):
  match reply:
    case Done{(pending,material)}:
      do IO<Result<&1,&1,U32 & String,Connection>>:
        header : Maybe<&1,List<&2,U32>> <- exporter_proof(material,seed)
        result : Result<&1,&1,U32 & String,WS.RelaySocket & (U32 & Bool)> <- WS.upgrade(pending,header)
        upgraded(result,seed)
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Connection>,Fail{error})

def connect_with_key(key: Result<&1,&1,U32 & String,List<&2,U32>>, url: String,
    seed: List<&2,U32>, max_version: U32) -> IO(Result<&1,&1,U32 & String,Connection>):
  match key:
    case Done{public}:
      do IO<Result<&1,&1,U32 & String,Connection>>:
        reply : Result<&1,&1,U32 & String,WS.PendingUpgrade & Maybe<&1,List<&2,U32>>> <-
          WS.prepare(url,max_version,public)
        prepared(reply,seed)
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Connection>,Fail{error})

def connect_with_version(url: String, +seed: List<&2,U32>, max_version: U32) -> IO(Result<&1,&1,U32 & String,Connection>):
  do IO<Result<&1,&1,U32 & String,Connection>>:
    key : Result<&1,&1,U32 & String,List<&2,U32>> <- Ed.public_key(seed)
    connect_with_key(key,url,seed,max_version)

def connect(url: String, seed: List<&2,U32>) -> IO(Result<&1,&1,U32 & String, Connection>):
  connect_with_version(url, seed, 2)

def received(reply: Result<&1,&1,U32 & String, WS.RelaySocket & List<&2,U32>>,
    +protocol: Wire.Version) -> Result<&1,&1,U32 & String, Connection & Wire.Frame>:
  match reply:
    case Done{(socket, bytes)}:
      Done{(Online{socket, protocol}, Wire.decode(Wire.ToClient{}, protocol, bytes))}
    case Fail{error}:
      Fail{error}

def receive(conn: Connection) -> IO(Result<&1,&1,U32 & String, Connection & Wire.Frame>):
  match conn:
    case Online{socket, protocol}:
      do IO<Result<&1,&1,U32 & String, Connection & Wire.Frame>>:
        reply : Result<&1,&1,U32 & String, WS.RelaySocket & List<&2,U32>> <- WS.recv(socket)
        return received(reply, protocol)

def sent(reply: Result<&1,&1,U32 & String, WS.RelaySocket>, protocol: Wire.Version) ->
    Result<&1,&1,U32 & String, Connection>:
  match reply:
    case Done{socket}:
      Done{Online{socket, protocol}}
    case Fail{error}:
      Fail{error}

def send_wire(socket: WS.RelaySocket, protocol: Wire.Version, encoded: Wire.Encoding) ->
    IO(Result<&1,&1,U32 & String, Connection>):
  match encoded:
    case Wire.Encoded{bytes}:
      do IO<Result<&1,&1,U32 & String, Connection>>:
        reply : Result<&1,&1,U32 & String, WS.RelaySocket> <- WS.send(socket, bytes)
        return sent(reply, protocol)
    case Wire.Rejected{_}:
      fail_open(socket, "invalid relay frame")

def send_datagram(conn: Connection, peer: List<&2,U32>, ecn: U32, segment: U32, data: List<&2,U32>) ->
    IO(Result<&1,&1,U32 & String, Connection>):
  match conn:
    case Online{socket, +protocol}:
      send_wire(socket, protocol, Wire.encode_datagram(Wire.ToRelay{}, protocol, peer, ecn, segment, data))

def pong(conn: Connection, data: List<&2,U32>) -> IO(Result<&1,&1,U32 & String, Connection>):
  match conn:
    case Online{socket, +protocol}:
      send_wire(socket, protocol, Wire.encode(Wire.ToRelay{}, protocol, 10, data))
