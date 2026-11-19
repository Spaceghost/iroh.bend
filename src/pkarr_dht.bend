import Base
import ./bencode.bend as Ben
import ./discovery.bend as Bytes
import ./ed25519.bend as Ed
import ./krpc.bend as Krpc
import ./pkarr.bend as Pkarr
import ./pkarr_dht_socket.bend as Net

type Peer is Data:
  DhtPeer{host: String, port: U32}

type Query is Data:
  DhtQuery{peer: Peer, tx: List<&2,U32>, payload: List<&2,U32>, timeout: U32}

type Read is Data:
  ReceivedKrpc{reply: Krpc.Reply}
  IgnoreKrpc{}
  FailedKrpc{code: U32, message: String}

def source(peer: Peer, host: String, port: U32) -> Bool:
  DhtPeer{expected_host,expected_port} = peer
  String.eq(host,expected_host) && U32.is_eq(port,expected_port)

def inspected(reply: Krpc.Reply) -> Read:
  match reply:
    case Krpc.InvalidKrpcReply{}:
      IgnoreKrpc{}
    case _:
      ReceivedKrpc{reply}

def inspect(reply: Result<&1,&1,U32 & String,List<&2,U32>>, tx: List<&2,U32>) -> Read:
  match reply:
    case Done{data}:
      inspected(Krpc.reply(data,tx))
    case Fail{(code,message)}:
      FailedKrpc{code,message}

def continue_read(result: Socket & Result<&1,&1,U32 & String,List<&2,U32>>, tx: List<&2,U32>,
    next: Socket -> Read -> IO(Socket & Result<&1,&1,U32 & String,Krpc.Reply>))
    -> IO(Socket & Result<&1,&1,U32 & String,Krpc.Reply>):
  (socket,poll) = result
  next(socket,inspect(poll,tx))

def read_reply(+fuel: Nat, socket: Socket, +query: Query, read: Read)
    -> IO(Socket & Result<&1,&1,U32 & String,Krpc.Reply>):
  match fuel query read:
    case _ _ ReceivedKrpc{reply}:
      IO.pure(Socket & Result<&1,&1,U32 & String,Krpc.Reply>,(socket,Done{reply}))
    case _ _ FailedKrpc{code,message}:
      IO.pure(Socket & Result<&1,&1,U32 & String,Krpc.Reply>,(socket,Fail{(code,message)}))
    case 1n+k DhtQuery{DhtPeer{host,port},tx,_,ms} IgnoreKrpc{}:
      do IO<Socket & Result<&1,&1,U32 & String,Krpc.Reply>>:
        received : Socket & Result<&1,&1,U32 & String,List<&2,U32>> <- Net.dht_receive(socket,host,port,ms)
        continue_read(received,tx,next => result => read_reply(k,next,query,result))
    case 0n _ IgnoreKrpc{}:
      IO.pure(Socket & Result<&1,&1,U32 & String,Krpc.Reply>,(socket,Fail{(1,"too many unrelated DHT datagrams")}))

def sent(outcome: Socket & Result<&1,&1,U32 & String,Unit>, query: Query)
    -> IO(Socket & Result<&1,&1,U32 & String,Krpc.Reply>):
  match outcome:
    case (socket,Done{_}):
      read_reply(8n,socket,query,IgnoreKrpc{})
    case (socket,Fail{error}):
      IO.pure(Socket & Result<&1,&1,U32 & String,Krpc.Reply>,(socket,Fail{error}))

def exchange(socket: Socket, +query: Query)
    -> IO(Socket & Result<&1,&1,U32 & String,Krpc.Reply>):
  DhtQuery{DhtPeer{host,port},_,payload,ms} = query
  do IO<Socket & Result<&1,&1,U32 & String,Krpc.Reply>>:
    outcome : Socket & Result<&1,&1,U32 & String,Unit> <- Net.dht_send(socket,host,port,payload,ms)
    sent(outcome,query)

def tx(+value: U32) -> List<&2,U32>:
  [U32.shrn(value,24n),Bytes.high_byte(value,16n),Bytes.high_byte(value,8n),U32.and(value,255)]

def get_query(peer: Peer, node_id: List<&2,U32>, +transaction: List<&2,U32>,
    target: List<&2,U32>, ms: U32) -> Query:
  DhtQuery{peer,transaction,Krpc.get(node_id,transaction,target),ms}

def error_number(digits: List<&2,U32>) -> U32:
  match digits:
    case [a,b,c]:
      U32.add(U32.mul(U32.sub(a,48),100),U32.add(U32.mul(U32.sub(b,48),10),U32.sub(c,48)))
    case _:
      1

def invalid_reply() -> U32 & String:
  (1,"invalid DHT reply")

def responder(fields: List<&2,Ben.Value>) -> Maybe<&2,List<&2,U32>>:
  Krpc.exact(Krpc.text(Ben.get(fields,"id")),20)

def has_field(value: Maybe<&2,Ben.Value>) -> Bool:
  match value:
    case Some{_}:
      True{}
    case None{}:
      False{}

def resolved_item(key: List<&2,U32>, id: Maybe<&2,List<&2,U32>>, item: Maybe<&2,List<&2,U32>>,
    claims_mutable: Bool)
    -> IO(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>):
  match id item claims_mutable:
    case Some{_} Some{wire} _:
      do IO<Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>>:
        verified : Pkarr.Verification <- Pkarr.verify(key,wire)
        return Done{Some{verified}}
    case Some{_} None{} False{}:
      IO.pure(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>,Done{None{}})
    case _ _ _:
      IO.pure(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>,Fail{invalid_reply()})

def resolve_reply(reply: Result<&1,&1,U32 & String,Krpc.Reply>, key: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>):
  match reply:
    case Done{Krpc.KrpcResponse{+fields}}:
      resolved_item(key,responder(fields),Krpc.item(fields),
        has_field(Ben.get(fields,"k")) || has_field(Ben.get(fields,"sig")) || has_field(Ben.get(fields,"seq")))
    case Done{Krpc.KrpcError{code,_}}:
      IO.pure(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>,
        Fail{(error_number(code),"DHT get rejected")})
    case Done{_}:
      IO.pure(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>,Fail{invalid_reply()})
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>,Fail{error})

def finish_resolve(outcome: Socket & Result<&1,&1,U32 & String,Krpc.Reply>, key: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>):
  (socket,reply) = outcome
  do IO<Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>>:
    Socket.close(socket)
    resolve_reply(reply,key)

def start_resolve(bound: Result<&1,&1,U32 & String,Socket>, get: Query, key: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>):
  match bound:
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>,Fail{error})
    case Done{socket}:
      do IO<Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>>:
        outcome : Socket & Result<&1,&1,U32 & String,Krpc.Reply> <- exchange(socket,get)
        finish_resolve(outcome,key)

def target_and_random(hash: Result<&1,&1,U32 & String,List<&2,U32>>,
    random: Result<&1,&1,U32 & String,U32>) -> Result<&1,&1,U32 & String,List<&2,U32> & U32>:
  match hash random:
    case Done{target} Done{tx_id}:
      Done{(target,tx_id)}
    case Fail{error} _:
      Fail{error}
    case _ Fail{error}:
      Fail{error}

def prepare_query(length: Maybe<&2,List<&2,U32>>, key: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,List<&2,U32> & U32>):
  match length:
    case Some{_}:
      do IO<Result<&1,&1,U32 & String,List<&2,U32> & U32>>:
        target : Result<&1,&1,U32 & String,List<&2,U32>> <- Ed.sha1_public_key(key)
        random : Result<&1,&1,U32 & String,U32> <- IO.random_u32()
        return target_and_random(target,random)
    case None{}:
      IO.pure(Result<&1,&1,U32 & String,List<&2,U32> & U32>,Fail{(1,"DHT node ID must be 20 bytes")})

def resolve_prepared(prepared: Result<&1,&1,U32 & String,List<&2,U32> & U32>,
    peer: Peer, node_id: List<&2,U32>, key: List<&2,U32>, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>):
  match prepared:
    case Done{(target,random)}:
      do IO<Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>>:
        bound : Result<&1,&1,U32 & String,Socket> <- Net.dht_bind()
        start_resolve(bound,get_query(peer,node_id,tx(random),target,ms),key)
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>,Fail{error})

# Query one supplied DHT peer. A returned mutable value is signature
# checked against the requested endpoint, with its original timestamp.
def resolve_at(peer: Peer, +node_id: List<&2,U32>, +key: List<&2,U32>, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>):
  do IO<Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>>:
    prepared : Result<&1,&1,U32 & String,List<&2,U32> & U32> <-
      prepare_query(Krpc.exact(Some{node_id},20),key)
    resolve_prepared(prepared,peer,node_id,key,ms)

def accepted(id: Maybe<&2,List<&2,U32>>, expected: List<&2,U32>) -> Bool:
  match id:
    case Some{bytes}:
      Bytes.bytes_eq(bytes,expected)
    case None{}:
      False{}

def ack_ok(valid: Bool) -> Result<&1,&1,U32 & String,Unit>:
  match valid:
    case True{}:
      Done{Unit{}}
    case False{}:
      Fail{invalid_reply()}

def ack(reply: Result<&1,&1,U32 & String,Krpc.Reply>, id: List<&2,U32>)
    -> Result<&1,&1,U32 & String,Unit>:
  match reply:
    case Done{Krpc.KrpcResponse{fields}}:
      ack_ok(accepted(responder(fields),id))
    case Done{Krpc.KrpcError{code,_}}:
      Fail{(error_number(code),"DHT put rejected")}
    case Done{_}:
      Fail{invalid_reply()}
    case Fail{error}:
      Fail{error}

def finish_publish(outcome: Socket & Result<&1,&1,U32 & String,Krpc.Reply>, id: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,Unit>):
  (socket,reply) = outcome
  do IO<Result<&1,&1,U32 & String,Unit>>:
    Socket.close(socket)
    return ack(reply,id)

def publish_error(socket: Socket, error: U32 & String) -> IO(Result<&1,&1,U32 & String,Unit>):
  do IO<Result<&1,&1,U32 & String,Unit>>:
    Socket.close(socket)
    return Fail{error}

def send_put(socket: Socket, peer: Peer, transaction: List<&2,U32>, ms: U32,
    id: Maybe<&2,List<&2,U32>>, bytes: Maybe<&2,List<&2,U32>>)
    -> IO(Result<&1,&1,U32 & String,Unit>):
  match id bytes:
    case Some{expected} Some{payload}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        outcome : Socket & Result<&1,&1,U32 & String,Krpc.Reply> <-
          exchange(socket,DhtQuery{peer,transaction,payload,ms})
        finish_publish(outcome,expected)
    case _ _:
      publish_error(socket,(1,"invalid DHT write token, responder, or sequence"))

def put_body(token: Maybe<&2,List<&2,U32>>, id: List<&2,U32>, transaction: List<&2,U32>,
    item: Pkarr.Signed) -> Maybe<&2,List<&2,U32>>:
  match token:
    case Some{Con{first,tail}}:
      Krpc.put(id,transaction,Con{first,tail},item)
    case _:
      None{}

def use_token(outcome: Socket & Result<&1,&1,U32 & String,Krpc.Reply>, peer: Peer, id: List<&2,U32>,
    +transaction: List<&2,U32>, item: Pkarr.Signed, ms: U32) -> IO(Result<&1,&1,U32 & String,Unit>):
  match outcome:
    case (socket,Done{Krpc.KrpcResponse{+fields}}):
      send_put(socket,peer,transaction,ms,responder(fields),
        put_body(Krpc.text(Ben.get(fields,"token")),id,transaction,item))
    case (socket,Done{Krpc.KrpcError{code,_}}):
      publish_error(socket,(error_number(code),"DHT token request rejected"))
    case (socket,Done{_}):
      publish_error(socket,invalid_reply())
    case (socket,Fail{error}):
      publish_error(socket,error)

def start_publish(bound: Result<&1,&1,U32 & String,Socket>, +peer: Peer, +node_id: List<&2,U32>,
    target: List<&2,U32>, +random: U32, item: Pkarr.Signed, +ms: U32)
    -> IO(Result<&1,&1,U32 & String,Unit>):
  match bound:
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Unit>,Fail{error})
    case Done{socket}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        outcome : Socket & Result<&1,&1,U32 & String,Krpc.Reply> <-
          exchange(socket,get_query(peer,node_id,tx(random),target,ms))
        use_token(outcome,peer,node_id,tx(U32.inc(random)),item,ms)

def publish_prepared(prepared: Result<&1,&1,U32 & String,List<&2,U32> & U32>,
    peer: Peer, node_id: List<&2,U32>, item: Pkarr.Signed, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Unit>):
  match prepared:
    case Done{(target,random)}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        bound : Result<&1,&1,U32 & String,Socket> <- Net.dht_bind()
        start_publish(bound,peer,node_id,target,random,item,ms)
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Unit>,Fail{error})

def verified_publish(proof: Pkarr.Verification, peer: Peer, +id: List<&2,U32>,
    key: List<&2,U32>, item: Pkarr.Signed, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Unit>):
  match proof:
    case Pkarr.Verified{_,_}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        prepared : Result<&1,&1,U32 & String,List<&2,U32> & U32> <-
          prepare_query(Krpc.exact(Some{id},20),key)
        publish_prepared(prepared,peer,id,item,ms)
    case _:
      IO.pure(Result<&1,&1,U32 & String,Unit>,Fail{(1,"invalid signed Pkarr endpoint packet")})

# Obtain a write token and put the signed mutable item on one supplied peer.
# Both requests use the same UDP socket.
def publish_at(peer: Peer, id: List<&2,U32>, +key: List<&2,U32>, +wire: List<&2,U32>, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Unit>):
  do IO<Result<&1,&1,U32 & String,Unit>>:
    proof : Pkarr.Verification <- Pkarr.verify(key,wire)
    verified_publish(proof,peer,id,key,Pkarr.parse(wire),ms)
