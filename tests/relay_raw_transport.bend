import Base
import ../src/relay_server_socket.bend as Net
import ../src/relay_http.bend as Http
import ../src/relay_raw_http.bend as Raw
import ../src/relay_websocket.bend as Ws

type WirePeer is Data:
  Opening{reader: Http.Reader}
  Framed{decoder: Ws.Decoder}
  MeteredChunk{decoder: Ws.Decoder, size: U32}

type PeerEntry is Data:
  WireEntry{id: U32, peer: WirePeer}

def peer_id(entry: PeerEntry) -> U32:
  WireEntry{id,_} = entry
  id

def peer_state(entry: PeerEntry) -> WirePeer:
  WireEntry{_,state} = entry
  state

def take(peers: List<&2,PeerEntry>, +id: U32, previous: PeerEntry, reversed: List<&2,PeerEntry>,
    found: Bool) -> List<&2,PeerEntry> & Maybe<&2,WirePeer>:
  match peers found:
    case tail True{}:
      (List.append(&2,PeerEntry,List.reverse(&2,PeerEntry,reversed),tail),Some{peer_state(previous)})
    case Nil{} False{}:
      (List.reverse(&2,PeerEntry,Con{previous,reversed}),None{})
    case Con{+entry,tail} False{}:
      take(tail,id,entry,Con{previous,reversed},U32.is_eq(peer_id(entry),id))

def partition(peers: List<&2,PeerEntry>, +id: U32) -> List<&2,PeerEntry> & Maybe<&2,WirePeer>:
  match peers:
    case Nil{}:
      ([],None{})
    case Con{+entry,tail}:
      take(tail,id,entry,[],U32.is_eq(peer_id(entry),id))

def flush(socket: Net.ServerSocket & Bool, id: U32) -> IO(Net.ServerSocket):
  match socket:
    case (net,True{}):
      IO.pure(Net.ServerSocket,net)
    case (net,False{}):
      Net.relay_kick(net,id,0)

def queue(net: Net.ServerSocket, +id: U32, bytes: List<&2,U32>) -> IO(Net.ServerSocket):
  do IO<Net.ServerSocket>:
    result : Net.ServerSocket & Bool <- Net.relay_queue(net,id,bytes)
    flush(result,id)

def send_frame(net: Net.ServerSocket, +id: U32, encoded: Maybe<&2,List<&2,U32>>) -> IO(Net.ServerSocket):
  match encoded:
    case Some{bytes}:
      queue(net,id,bytes)
    case None{}:
      Net.relay_kick(net,id,0)

def drop_after(net: Net.ServerSocket, id: U32, flush: U32)
    -> IO(Net.ServerSocket & Maybe<&2,WirePeer>):
  do IO<Net.ServerSocket & Maybe<&2,WirePeer>>:
    closed : Net.ServerSocket <- Net.relay_kick(net,id,flush)
    return (closed,None{})

def complete_chunk(net: Net.ServerSocket, +id: U32) -> IO(Net.ServerSocket):
  do IO<Net.ServerSocket>:
    resumed : Net.ServerSocket <- Net.relay_resume_rx(net,id)
    Net.relay_raw_chunk_done(resumed,id)

def drive_frames(fuel: Nat, net: Net.ServerSocket, +id: U32, read: Ws.Read)
    -> IO(Net.ServerSocket & Maybe<&2,WirePeer>):
  match fuel read:
    case _ Ws.Waiting{next}:
      do IO<Net.ServerSocket & Maybe<&2,WirePeer>>:
        resumed : Net.ServerSocket <- complete_chunk(net,id)
        return (resumed,Some{Framed{next}})
    case 1n+left Ws.Received{Ws.Ping{bytes},next,rest}:
      do IO<Net.ServerSocket & Maybe<&2,WirePeer>>:
        sent : Net.ServerSocket <- send_frame(net,id,Ws.encode(Ws.Pong{bytes}))
        drive_frames(left,sent,id,Ws.receive(next,rest,65544))
    case 1n+left Ws.Received{Ws.Binary{bytes},next,rest}:
      do IO<Net.ServerSocket & Maybe<&2,WirePeer>>:
        sent : Net.ServerSocket <- send_frame(net,id,Ws.encode(Ws.Binary{bytes}))
        drive_frames(left,sent,id,Ws.receive(next,rest,65544))
    case 1n+left Ws.Received{Ws.CloseFrame{bytes},_,_}:
      do IO<Net.ServerSocket & Maybe<&2,WirePeer>>:
        sent : Net.ServerSocket <- send_frame(net,id,Ws.encode(Ws.CloseFrame{bytes}))
        drop_after(sent,id,1)
    case 1n+left Ws.Received{_,next,rest}:
      drive_frames(left,net,id,Ws.receive(next,rest,65544))
    case _ _:
      drop_after(net,id,0)

def started(net: Net.ServerSocket, +id: U32, result: Raw.UpgradeRead)
    -> IO(Net.ServerSocket & Maybe<&2,WirePeer>):
  match result:
    case Raw.MoreHttp{state}:
      do IO<Net.ServerSocket & Maybe<&2,WirePeer>>:
        resumed : Net.ServerSocket <- complete_chunk(net,id)
        return (resumed,Some{Opening{state}})
    case Raw.WebSocketReady{_,_,reply,pending}:
      do IO<Net.ServerSocket & Maybe<&2,WirePeer>>:
        accepted : Net.ServerSocket <- queue(net,id,reply)
        active : Net.ServerSocket <- Net.relay_authorized_with_meter(accepted,id,True{})
        drive_frames(32768n,active,id,Ws.receive(Ws.decoder(),pending,65544))
    case _:
      drop_after(net,id,0)

def checked_chunk(net: Net.ServerSocket, id: U32, decoder: Ws.Decoder, bytes: List<&2,U32>, same: Bool)
    -> IO(Net.ServerSocket & Maybe<&2,WirePeer>):
  match same:
    case True{}:
      drive_frames(32768n,net,id,Ws.receive(decoder,bytes,65544))
    case False{}:
      drop_after(net,id,0)

def ingest(net: Net.ServerSocket, +id: U32, state: Maybe<&2,WirePeer>, +bytes: List<&2,U32>)
    -> IO(Net.ServerSocket & Maybe<&2,WirePeer>):
  match state:
    case Some{Opening{reader}}:
      do IO<Net.ServerSocket & Maybe<&2,WirePeer>>:
        step : Raw.UpgradeRead <- Raw.receive(reader,bytes)
        started(net,id,step)
    case Some{MeteredChunk{decoder,size}}:
      checked_chunk(net,id,decoder,bytes,U32.is_eq(size,U32.from_nat(List.length(&2,U32,bytes))))
    case _:
      drop_after(net,id,0)

def keep(peers: List<&2,PeerEntry>, id: U32, state: Maybe<&2,WirePeer>) -> List<&2,PeerEntry>:
  match state:
    case Some{peer}:
      Con{WireEntry{id,peer},peers}
    case None{}:
      peers

def drop_entry(result: List<&2,PeerEntry> & Maybe<&2,WirePeer>) -> List<&2,PeerEntry>:
  (peers,_) = result
  peers

def retain(result: Net.ServerSocket & Maybe<&2,WirePeer>, peers: List<&2,PeerEntry>, id: U32)
    -> Net.ServerSocket & List<&2,PeerEntry>:
  (net,peer) = result
  (net,keep(peers,id,peer))

def deliver(net: Net.ServerSocket, +id: U32, bytes: List<&2,U32>,
    partitioned: List<&2,PeerEntry> & Maybe<&2,WirePeer>) -> IO(Net.ServerSocket & List<&2,PeerEntry>):
  (others,before) = partitioned
  do IO<Net.ServerSocket & List<&2,PeerEntry>>:
    result : Net.ServerSocket & Maybe<&2,WirePeer> <- ingest(net,id,before,bytes)
    return retain(result,others,id)

def charged(partitioned: List<&2,PeerEntry> & Maybe<&2,WirePeer>, id: U32, size: U32)
    -> List<&2,PeerEntry>:
  match partitioned:
    case (rest,Some{Framed{decoder}}):
      Con{WireEntry{id,MeteredChunk{decoder,size}},rest}
    case (rest,peer):
      keep(rest,id,peer)

def dispatch(polled: Net.ServerSocket & Net.SocketEvent, +peers: List<&2,PeerEntry>)
    -> IO(Net.ServerSocket & List<&2,PeerEntry>):
  match polled:
    case (net,Net.RelayJoined{id,0}):
      IO.pure(Net.ServerSocket & List<&2,PeerEntry>,(net,Con{WireEntry{id,Opening{Http.reader()}},peers}))
    case (net,Net.RelayLeft{id}):
      IO.pure(Net.ServerSocket & List<&2,PeerEntry>,(net,drop_entry(partition(peers,id))))
    case (net,Net.RelayBytes{+id,bytes}):
      deliver(net,id,bytes,partition(peers,id))
    case (net,Net.RelayRead{+id,size}):
      IO.pure(Net.ServerSocket & List<&2,PeerEntry>,(net,charged(partition(peers,id),id,size)))
    case (net,_):
      IO.pure(Net.ServerSocket & List<&2,PeerEntry>,(net,peers))

def poll_pair(socket: Net.ServerSocket & List<&2,PeerEntry>) -> IO(Net.ServerSocket & List<&2,PeerEntry>):
  (net,peers) = socket
  do IO<Net.ServerSocket & List<&2,PeerEntry>>:
    event : Net.ServerSocket & Net.SocketEvent <- Net.relay_poll(net)
    dispatch(event,peers)

def stop(socket: Net.ServerSocket & List<&2,PeerEntry>) -> IO(Unit):
  (net,_) = socket
  Net.relay_stop(net)

def run(fuel: Nat, socket: Net.ServerSocket & List<&2,PeerEntry>) -> IO(Unit):
  match fuel:
    case 0n:
      stop(socket)
    case 1n+left:
      do IO<Unit>:
        next : Net.ServerSocket & List<&2,PeerEntry> <- poll_pair(socket)
        IO.sleep(1)
        run(left,next)

def start(bound: Net.ServerSocket & U32) -> IO(Unit):
  (net,port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    run(20000n,(net,[]))

def serve(cert: String, key: String) -> IO(Unit):
  do IO<Unit>:
    bound : Net.ServerSocket & U32 <- IO.try(Net.ServerSocket & U32,Net.relay_bind_raw("127.0.0.1",0,cert,key))
    start(bound)

def args(argv: List<String>) -> IO(Unit):
  match argv:
    case [_,cert,key]:
      serve(cert,key)
    case _:
      serve("","")

def main() -> IO(Unit):
  do IO<Unit>:
    argv : List<String> <- IO.args()
    args(argv)
