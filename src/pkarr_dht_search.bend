import Base
import ./bencode.bend as Ben
import ./discovery.bend as Bytes
import ./krpc.bend as Krpc
import ./pkarr.bend as Pkarr
import ./pkarr_dht.bend as Dht

type Contact is Data:
  Candidate{peer: Dht.Peer, id: Maybe<&2,List<&2,U32>>, distance: List<&2,U32>}

type Destination is Data:
  Writable{peer: Dht.Peer, id: List<&2,U32>, distance: List<&2,U32>, token: List<&2,U32>}

type Item is Data:
  Authentic{timestamp: List<&2,U32>, value: List<&2,U32>, proof: Pkarr.Verification}
  NoItem{}

type Search is Data:
  Shortlist{queue: List<&2,Contact>, seen: List<&2,Dht.Peer>,
    writable: List<&2,Destination>, best: Item, replies: U32}

type Context is Data:
  Target{key: List<&2,U32>, digest: List<&2,U32>, local_id: List<&2,U32>, timeout: U32}

def distance(id: List<&2,U32>, target: List<&2,U32>) -> List<&2,U32>:
  match id target:
    case Con{a,rest} Con{b,tail}:
      Con{U32.xor(a,b),distance(rest,tail)}
    case _ _:
      []

def peer_eq(peer: Dht.Peer, other: Dht.Peer) -> Bool:
  Dht.DhtPeer{host,port} = other
  Dht.source(peer,host,port)

def known(peer: Dht.Peer, id: Maybe<&2,List<&2,U32>>, digest: List<&2,U32>) -> Contact:
  match id:
    case Some{+bytes}:
      Candidate{peer,Some{bytes},distance(bytes,digest)}
    case None{}:
      Candidate{peer,None{},[]}

def queued(queue: List<&2,Contact>, +p: Dht.Peer) -> Bool:
  match queue:
    case Nil{}:
      False{}
    case Con{Candidate{peer,_,_},tail}:
      peer_eq(p,peer) || queued(tail,p)

def earlier(left: Contact, right: Contact) -> Bool:
  Candidate{_,_,a} = left
  Candidate{_,_,b} = right
  Ben.less(a,b)

def insert_choice(new: Contact, head: Contact, tail: List<&2,Contact>,
    later: List<&2,Contact>, first: Bool) -> List<&2,Contact>:
  match first:
    case True{}:
      Con{new,Con{head,tail}}
    case False{}:
      Con{head,later}

def insert(queue: List<&2,Contact>, +new: Contact) -> List<&2,Contact>:
  match queue:
    case Nil{}:
      [new]
    case Con{+head,+tail}:
      insert_choice(new,head,tail,insert(tail,new),earlier(new,head))

def enqueue(queue: List<&2,Contact>, candidate: Contact, duplicate: Bool) -> List<&2,Contact>:
  match duplicate:
    case True{}:
      queue
    case False{}:
      List.take(&2,Contact,insert(queue,candidate),32n)

def add_contact(+queue: List<&2,Contact>, seen: List<&2,Dht.Peer>, +peer: Dht.Peer,
    node: Maybe<&2,List<&2,U32>>, digest: List<&2,U32>) -> List<&2,Contact>:
  enqueue(queue,known(peer,node,digest),queued(queue,peer) ||
    List.contains(Dht.Peer,peer_eq,seen,peer))

def ipv4(a: U32, b: U32, c: U32, d: U32) -> String:
  left = String.append(U32.show(a),String.append(".",U32.show(b)))
  right = String.append(U32.show(c),String.append(".",U32.show(d)))
  String.append(left,String.append(".",right))

def usable_node(queue: List<&2,Contact>, seen: List<&2,Dht.Peer>, peer: Dht.Peer,
    id: List<&2,U32>, digest: List<&2,U32>, usable: Bool) -> List<&2,Contact>:
  match usable:
    case True{}:
      add_contact(queue,seen,peer,Some{id},digest)
    case False{}:
      queue

def referrals(nodes: List<&2,Krpc.CompactNode>, queue: List<&2,Contact>,
    +seen: List<&2,Dht.Peer>, +digest: List<&2,U32>) -> List<&2,Contact>:
  match nodes:
    case Nil{}:
      queue
    case Con{Krpc.CompactV4{id,+a,b,c,d,+port},tail}:
      referrals(tail,usable_node(queue,seen,Dht.DhtPeer{ipv4(a,b,c,d),port},id,digest,
        U32.is_gt(a,0) && U32.is_lt(a,224) && U32.is_gt(port,0)),seen,digest)

def seeds(peers: List<&2,Dht.Peer>, queue: List<&2,Contact>) -> List<&2,Contact>:
  match peers:
    case Nil{}:
      queue
    case Con{peer,tail}:
      seeds(tail,add_contact(queue,[],peer,None{},[]))

def prefer(old: Item, fresh: Item, replace: Bool) -> Item:
  match replace:
    case True{}:
      fresh
    case False{}:
      old

def newest(+old: Item, +fresh: Item) -> Item:
  match old fresh:
    case NoItem{} _:
      fresh
    case _ NoItem{}:
      old
    case Authentic{+a,av,_} Authentic{+b,bv,_}:
      prefer(old,fresh,Ben.less(a,b) || (Bytes.bytes_eq(a,b) && Ben.less(av,bv)))

def verify_value(value: Pkarr.Signed, proof: Pkarr.Verification) -> Item:
  match value proof:
    case Pkarr.Envelope{_,_,stamp,dns} Pkarr.Verified{time,records}:
      Authentic{stamp,dns,Pkarr.Verified{time,records}}
    case _ _:
      NoItem{}

def verify_item(item: Maybe<&2,List<&2,U32>>, key: List<&2,U32>) -> IO(Item):
  match item:
    case Some{+wire}:
      do IO<Item>:
        proof : Pkarr.Verification <- Pkarr.verify(key,wire)
        return verify_value(Pkarr.parse(wire),proof)
    case None{}:
      IO.pure(Item,NoItem{})

def by_distance(left: Destination, right: Destination) -> Bool:
  Writable{_,_,a,_} = left
  Writable{_,_,b,_} = right
  Ben.less(a,b)

def same_responder(left: Destination, right: Destination) -> Bool:
  Writable{_,a,_,_} = left
  Writable{_,b,_,_} = right
  Bytes.bytes_eq(a,b)

def remember_destination(peers: List<&2,Destination>, entry: Destination, duplicate: Bool)
    -> List<&2,Destination>:
  match duplicate:
    case True{}:
      peers
    case False{}:
      Con{entry,peers}

def write_peer(+peers: List<&2,Destination>, token: Maybe<&2,List<&2,U32>>,
    peer: Dht.Peer, +id: List<&2,U32>, digest: List<&2,U32>) -> List<&2,Destination>:
  match token:
    case Some{Con{first,tail}}:
      +entry : Destination = Writable{peer,id,distance(id,digest),Con{first,tail}}
      remember_destination(peers,entry,List.contains(Destination,same_responder,peers,entry))
    case _:
      peers

def records(state: Search, fresh: Item) -> Search:
  Shortlist{queue,seen,peers,best,count} = state
  Shortlist{queue,seen,peers,newest(best,fresh),count}

def learn(state: Search, +fields: List<&2,Ben.Value>, peer: Dht.Peer,
    id: List<&2,U32>, key: List<&2,U32>, +digest: List<&2,U32>) -> IO(Search):
  Shortlist{queue,+seen,peers,best,count} = state
  next = referrals(Krpc.nodes(Krpc.text(Ben.get(fields,"nodes"))),queue,seen,digest)
  eligible = write_peer(peers,Krpc.text(Ben.get(fields,"token")),peer,id,digest)
  do IO<Search>:
    fresh : Item <- verify_item(Krpc.item(fields),key)
    return records(Shortlist{next,seen,eligible,best,U32.inc(count)},fresh)

def matched_id(expected: Maybe<&2,List<&2,U32>>, actual: List<&2,U32>) -> Bool:
  match expected:
    case None{}:
      True{}
    case Some{id}:
      Bytes.bytes_eq(id,actual)

def learn_id(state: Search, fields: List<&2,Ben.Value>, peer: Dht.Peer, key: List<&2,U32>,
    digest: List<&2,U32>, id: List<&2,U32>, matched: Bool) -> IO(Search):
  match matched:
    case True{}:
      learn(state,fields,peer,id,key,digest)
    case False{}:
      IO.pure(Search,state)

def learns(state: Search, fields: List<&2,Ben.Value>, peer: Dht.Peer, key: List<&2,U32>,
    digest: List<&2,U32>, expected: Maybe<&2,List<&2,U32>>, id: Maybe<&2,List<&2,U32>>)
    -> IO(Search):
  match id:
    case Some{+actual}:
      learn_id(state,fields,peer,key,digest,actual,matched_id(expected,actual))
    case None{}:
      IO.pure(Search,state)

def observe(state: Search, contact: Contact, context: Context,
    reply: Result<&1,&1,U32 & String,Krpc.Reply>) -> IO(Search):
  match contact context reply:
    case Candidate{peer,id,_} Target{key,digest,_,_} Done{Krpc.KrpcResponse{+fields}}:
      learns(state,fields,peer,key,digest,id,Dht.responder(fields))
    case _ _ _:
      IO.pure(Search,state)

def after_get(outcome: Socket & Result<&1,&1,U32 & String,Krpc.Reply>,
    state: Search, contact: Contact, context: Context,
    proceed: Socket -> Search -> IO(Socket & Search)) -> IO(Socket & Search):
  (socket,reply) = outcome
  do IO<Socket & Search>:
    learned : Search <- observe(state,contact,context,reply)
    proceed(socket,learned)

def query_for(+contact: Contact, context: Context, transaction: U32) -> Dht.Query:
  Candidate{peer,_,_} = contact
  Target{_,digest,local_id,ms} = context
  Dht.get_query(peer,local_id,Dht.tx(transaction),digest,ms)

def lookup(+fuel: Nat, socket: Socket, +state: Search, +context: Context, +transaction: U32)
    -> IO(Socket & Search):
  match fuel state:
    case 1n+left Shortlist{Con{+contact,tail},seen,peers,best,count}:
      Candidate{peer,_,_} = contact
      do IO<Socket & Search>:
        outcome : Socket & Result<&1,&1,U32 & String,Krpc.Reply> <-
          Dht.exchange(socket,query_for(contact,context,transaction))
        after_get(outcome,Shortlist{tail,Con{peer,seen},peers,best,count},contact,context,
          next => updated => lookup(left,next,updated,context,U32.inc(transaction)))
    case _ _:
      IO.pure(Socket & Search,(socket,state))

def found(best: Item, replies: U32) -> Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>:
  match best replies:
    case Authentic{_,_,proof} _:
      Done{Some{proof}}
    case _ 0:
      Fail{(1,"no DHT peer answered")}
    case _ _:
      Done{None{}}

def resolved(unused_transaction: U32, result: Socket & Search) -> IO(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>):
  (socket,state) = result
  Shortlist{_,_,_,best,replies} = state
  do IO<Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>>:
    Socket.close(socket)
    return found(best,replies)

def search(-R: Type, initial: Result<&1,&1,U32 & String,Socket>, state: Search,
    context: Context, +transaction: U32,
    finished: U32 -> (Socket & Search) -> IO(Result<&1,&1,U32 & String,R>))
    -> IO(Result<&1,&1,U32 & String,R>):
  match initial:
    case Done{socket}:
      do IO<Result<&1,&1,U32 & String,R>>:
        result : Socket & Search <- lookup(64n,socket,state,context,transaction)
        finished(U32.add(transaction,64),result)
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,R>,Fail{error})

def begin(-R: Type, prepared: Result<&1,&1,U32 & String,List<&2,U32> & U32>, bootstrap: List<&2,Dht.Peer>,
    id: List<&2,U32>, key: List<&2,U32>, ms: U32,
    finished: U32 -> (Socket & Search) -> IO(Result<&1,&1,U32 & String,R>))
    -> IO(Result<&1,&1,U32 & String,R>):
  match prepared:
    case Done{(digest,transaction)}:
      do IO<Result<&1,&1,U32 & String,R>>:
        initial : Result<&1,&1,U32 & String,Socket> <- UDP.bind("0.0.0.0",0)
        search(R,initial,Shortlist{seeds(bootstrap,[]),[],[],NoItem{},0},
          Target{key,digest,id,ms},transaction,finished)
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,R>,Fail{error})

# Follow compact IPv4 referrals in XOR-distance order. Select the greatest
# sequence among verified packets, breaking equal-sequence ties by DNS bytes.
def resolve(bootstrap: List<&2,Dht.Peer>, +id: List<&2,U32>, +key: List<&2,U32>, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>):
  do IO<Result<&1,&1,U32 & String,Maybe<&2,Pkarr.Verification>>>:
    prepared : Result<&1,&1,U32 & String,List<&2,U32> & U32> <- Dht.prepare_query(Krpc.exact(Some{id},20),key)
    begin(Maybe<&2,Pkarr.Verification>,prepared,bootstrap,id,key,ms,resolved)

type Publication is Data:
  PublishItem{local_id: List<&2,U32>, item: Pkarr.Signed, timeout: U32}

def put_request(peer: Dht.Peer, tx: List<&2,U32>, ms: U32, packet: Maybe<&2,List<&2,U32>>)
    -> Maybe<&2,Dht.Query>:
  match packet:
    case Some{payload}:
      Some{Dht.DhtQuery{peer,tx,payload,ms}}
    case None{}:
      None{}

def put_query(destination: Destination, publication: Publication, +transaction: List<&2,U32>)
    -> Maybe<&2,Dht.Query>:
  Writable{peer,_,_,token} = destination
  PublishItem{id,item,ms} = publication
  put_request(peer,transaction,ms,Krpc.put(id,transaction,token,item))

def wrote(outcome: Socket & Result<&1,&1,U32 & String,Krpc.Reply>, id: List<&2,U32>,
    next: Socket -> Result<&1,&1,U32 & String,Unit> -> IO(Result<&1,&1,U32 & String,U32>))
    -> IO(Result<&1,&1,U32 & String,U32>):
  (socket,reply) = outcome
  next(socket,Dht.ack(reply,id))

def count_ack(result: Result<&1,&1,U32 & String,Unit>, count: U32) -> U32:
  match result:
    case Done{_}:
      U32.inc(count)
    case Fail{_}:
      count

def publication_result(count: U32) -> Result<&1,&1,U32 & String,U32>:
  match count:
    case 0:
      Fail{(1,"no DHT peer accepted the publication")}
    case _:
      Done{count}

def finish_writes(socket: Socket, count: U32) -> IO(Result<&1,&1,U32 & String,U32>):
  do IO<Result<&1,&1,U32 & String,U32>>:
    Socket.close(socket)
    return publication_result(count)

def write_to(socket: Socket, candidate: Maybe<&2,Dht.Query>, id: List<&2,U32>, count: U32,
    proceed: Socket -> Result<&1,&1,U32 & String,Unit> -> IO(Result<&1,&1,U32 & String,U32>))
    -> IO(Result<&1,&1,U32 & String,U32>):
  match candidate:
    case Some{query}:
      do IO<Result<&1,&1,U32 & String,U32>>:
        outcome : Socket & Result<&1,&1,U32 & String,Krpc.Reply> <- Dht.exchange(socket,query)
        wrote(outcome,id,proceed)
    case None{}:
      finish_writes(socket,count)

def write_all(peers: List<&2,Destination>, socket: Socket, +pub: Publication, +transaction: U32, +acks: U32)
    -> IO(Result<&1,&1,U32 & String,U32>):
  match peers acks:
    case _ 8:
      finish_writes(socket,acks)
    case Con{Writable{peer,+id,dist,token},tail} _:
      write_to(socket,put_query(Writable{peer,id,dist,token},pub,Dht.tx(transaction)),id,acks,
        next => result => write_all(tail,next,pub,U32.inc(transaction),count_ack(result,acks)))
    case Nil{} _:
      finish_writes(socket,acks)

def may_publish(best: Item, candidate: Pkarr.Signed) -> Bool:
  match best candidate:
    case NoItem{} Pkarr.Envelope{_,_,_,_}:
      True{}
    case Authentic{+remote,old,_} Pkarr.Envelope{_,_,+stamp,body}:
      Ben.less(remote,stamp) || (Bytes.bytes_eq(remote,stamp) && Bytes.bytes_eq(old,body))
    case _ _:
      False{}

def publish_if_fresh(socket: Socket, peers: List<&2,Destination>, pub: Publication, transaction: U32,
    fresh: Bool) -> IO(Result<&1,&1,U32 & String,U32>):
  match fresh:
    case True{}:
      write_all(List.sort(Destination,by_distance,peers),socket,pub,transaction,0)
    case False{}:
      do IO<Result<&1,&1,U32 & String,U32>>:
        Socket.close(socket)
        return Fail{(302,"DHT already has a newer or conflicting Pkarr record")}

def publish_found(+pub: Publication, transaction: U32, result: Socket & Search)
    -> IO(Result<&1,&1,U32 & String,U32>):
  PublishItem{_,item,_} = pub
  (socket,state) = result
  Shortlist{_,_,peers,best,_} = state
  publish_if_fresh(socket,peers,pub,transaction,may_publish(best,item))

def publish_sequence(sequence: Maybe<&2,List<&2,U32>>, item: Pkarr.Signed, bootstrap: List<&2,Dht.Peer>,
    +id: List<&2,U32>, +key: List<&2,U32>, +ms: U32)
    -> IO(Result<&1,&1,U32 & String,U32>):
  match sequence:
    case Some{_}:
      do IO<Result<&1,&1,U32 & String,U32>>:
        prepared : Result<&1,&1,U32 & String,List<&2,U32> & U32> <- Dht.prepare_query(Krpc.exact(Some{id},20),key)
        begin(U32,prepared,bootstrap,id,key,ms,publish_found(PublishItem{id,item,ms}))
    case None{}:
      IO.pure(Result<&1,&1,U32 & String,U32>,Fail{(1,"DHT requires a nonnegative signed 64-bit sequence")})

def publish_verified(proof: Pkarr.Verification, +item: Pkarr.Signed, bootstrap: List<&2,Dht.Peer>,
    +id: List<&2,U32>, key: List<&2,U32>, +ms: U32)
    -> IO(Result<&1,&1,U32 & String,U32>):
  match proof item:
    case Pkarr.Verified{_stamp,_records} Pkarr.Envelope{_,_,+stamp,_}:
      publish_sequence(Krpc.signed_timestamp(stamp),item,bootstrap,id,key,ms)
    case _ _:
      IO.pure(Result<&1,&1,U32 & String,U32>,Fail{(1,"invalid signed Pkarr endpoint packet")})

# Replicate to the closest peers that supplied tokens. Return the number of
# acknowledgements received (up to eight).
def publish(bootstrap: List<&2,Dht.Peer>, id: List<&2,U32>, +key: List<&2,U32>, +wire: List<&2,U32>, ms: U32)
    -> IO(Result<&1,&1,U32 & String,U32>):
  do IO<Result<&1,&1,U32 & String,U32>>:
    proof : Pkarr.Verification <- Pkarr.verify(key,wire)
    publish_verified(proof,Pkarr.parse(wire),bootstrap,id,key,ms)
