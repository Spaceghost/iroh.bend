import Base
import ./endpoint_ticket.bend as Tickets
import ./relay_url.bend as RelayUrl
import ./ip.bend as Ip
import ./ed25519.bend as Ed
import ./direct.bend as Direct
import ./discovery.bend as Dns
import ./lookup_socket.bend as LookupSocket
import ./pkarr.bend as Pkarr
import ./pkarr_http.bend as PkarrHttp
import ./relay_quic.bend as Path
import ./relay_quic_inbound.bend as Inbound
import ./quic_datagram.bend as Quic
import ./quic_close.bend as Close
import ./quic_nat.bend as NatWire
import ./quic_handshake_routes.bend as Race
import ./endpoint_dial.bend as Dial

type Address is Data:
  IpAddress{host: String, port: U32}

type Routes is Data:
  DialRoutes{direct: List<&2,Address>, relays: List<&2,String>}

type Identity is Data:
  PeerKeys{local_seed: List<&2,U32>, endpoint_id: List<&2,U32>, alpn: List<&2,U32>}

type Timeouts is Data:
  HandshakeTimeouts{direct_ms: U32, relay_ms: U32}

type DnsSource is Data:
  DnsResolver{origin: String, host: String, port: U32, timeout_ms: U32}

type AddressLookup is Data:
  DnsLookup{resolver: DnsSource}
  PkarrLookup{relay: String, timeout_ms: U32}

def Connected() -> Type:
  Direct.QuicConnection & Maybe<&1,Path.Bridge>

def Outcome() -> Type:
  Result<&1,&1,U32 & String,Connected()>

def Transport(-C: Type) -> Type:
  C & Maybe<&1,Path.Bridge>

def TransportResult(-C: Type) -> Type:
  Result<&1,&1,U32 & String,Transport(C)>

def Dialer(-C: Type) -> Type:
  Address -> Identity -> U32 -> IO(Result<&1,&1,U32 & String,C>)

def Connection() -> Type:
  Transport(Quic.DatagramConnection)

def ConnectResult() -> Type:
  TransportResult(Quic.DatagramConnection)

def ascii(bytes: List<&2,U32>) -> Bool:
  match bytes:
    case Nil{}:
      True{}
    case Con{+b,rest}:
      U32.is_ge(b,33) && U32.is_le(b,126) && ascii(rest)

def as_chars(bytes: List<&2,U32>) -> List<&2,Char>:
  match bytes:
    case Nil{}:
      []
    case Con{b,rest}:
      Con{Char.from_u32(b),as_chars(rest)}

def ip_result(host: String, port: U32, valid: Bool) -> Maybe<&2,Address>:
  match valid:
    case True{}:
      Some{IpAddress{host,port}}
    case False{}:
      None{}

def ip_port(+host: String, port: Maybe<&2,U32>) -> Maybe<&2,Address>:
  match port:
    case Some{+n}:
      ip_result(host,n,Bool.not(String.is_empty(host)) && U32.is_gt(n,0) && U32.is_le(n,65535))
    case None{}:
      None{}

def ipv4(parts: List<&2,String>) -> Maybe<&2,Address>:
  match parts:
    case [host,port]:
      ip_port(host,U32.read(port))
    case _:
      None{}

def ipv6_end(host: String, port: String, valid: Bool) -> Maybe<&2,Address>:
  match valid:
    case True{}:
      ip_port(String.drop(host,1n),U32.read(String.drop(port,1n)))
    case False{}:
      None{}

def ipv6(parts: List<&2,String>) -> Maybe<&2,Address>:
  match parts:
    case [host,+port]:
      ipv6_end(host,port,String.starts_with(port,":"))
    case _:
      None{}

def ip_text(text: String, bracketed: Bool) -> Maybe<&2,Address>:
  match bracketed:
    case True{}:
      ipv6(String.split(text,']'))
    case False{}:
      ipv4(String.split(text,':'))

def decoded_ip(bytes: List<&2,U32>, valid: Bool) -> Maybe<&2,Address>:
  match valid:
    case True{}:
      +text = String.from_list(as_chars(bytes))
      ip_text(text,String.starts_with(text,"["))
    case False{}:
      None{}

def address(+bytes: List<&2,U32>) -> Maybe<&2,Address>:
  decoded_ip(bytes,ascii(bytes))

def without_suffix(bytes: List<&2,U32>) -> List<&2,U32>:
  match bytes:
    case Con{63,_}:
      []
    case Con{35,_}:
      []
    case Con{byte,rest}:
      Con{byte,without_suffix(rest)}
    case Nil{}:
      []

def relay_segments(parts: List<&2,String>) -> List<&2,String>:
  match parts:
    case Nil{}:
      ["relay"]
    case Con{_,Nil{}}:
      ["relay"]
    case Con{head,tail}:
      Con{head,relay_segments(tail)}

def relay_parts(parts: List<&2,String>, scheme: String) -> Maybe<&2,String>:
  match parts:
    case Con{SNil{},_}:
      None{}
    case Con{authority,dirs}:
      Some{scheme ++ String.join(Con{authority,relay_segments(dirs)},"/")}
    case Nil{}:
      None{}

def relay_base(rest: String, scheme: String) -> Maybe<&2,String>:
  relay_parts(String.split(rest,'/'),scheme)

def websocket_url(text: String, http: Bool, https: Bool, ws: Bool, wss: Bool) -> Maybe<&2,String>:
  match http https ws wss:
    case True{} _ _ _:
      relay_base(String.drop(text,7n),"ws://")
    case _ True{} _ _:
      relay_base(String.drop(text,8n),"wss://")
    case _ _ True{} _:
      relay_base(String.drop(text,5n),"ws://")
    case _ _ _ True{}:
      relay_base(String.drop(text,6n),"wss://")
    case _ _ _ _:
      None{}

def decoded_relay(bytes: List<&2,U32>, valid: Bool) -> Maybe<&2,String>:
  match valid:
    case True{}:
      +text = String.from_list(as_chars(without_suffix(bytes)))
      websocket_url(text,String.starts_with(text,"http://"),String.starts_with(text,"https://"),
        String.starts_with(text,"ws://"),String.starts_with(text,"wss://"))
    case False{}:
      None{}

def canonical_relay(+bytes: List<&2,U32>) -> Maybe<&2,String>:
  decoded_relay(bytes,ascii(bytes))

def relay_url(bytes: List<&2,U32>) -> Maybe<&2,String>:
  Maybe.bind(&2,List<&2,U32>,String,RelayUrl.normalize(bytes),canonical => canonical_relay(canonical))

def add_ip(candidate: Maybe<&2,Address>, routes: Routes) -> Routes:
  match candidate routes:
    case Some{ip} DialRoutes{ips,relays}:
      DialRoutes{Con{ip,ips},relays}
    case _ _:
      routes

def add_relay(candidate: Maybe<&2,String>, routes: Routes) -> Routes:
  match candidate routes:
    case Some{url} DialRoutes{ips,urls}:
      DialRoutes{ips,Con{url,urls}}
    case _ _:
      routes

def routes(records: List<&2,Dns.Attribute>) -> Routes:
  match records:
    case Con{Dns.Address{value},rest}:
      add_ip(address(value),routes(rest))
    case Con{Dns.RelayUrl{value},rest}:
      add_relay(relay_url(value),routes(rest))
    case Con{Dns.UserData{_},rest}:
      routes(rest)
    case Nil{}:
      DialRoutes{[],[]}

# Project a decoded ticket onto the endpoint's built-in transports.
def ticket_routes(addresses: List<&2,Tickets.TransportAddress>) -> Routes:
  match addresses:
    case Nil{}:
      DialRoutes{[],[]}
    case Con{Tickets.IPv4{[a,b,c,d],port},rest}:
      add_ip(ip_port(Ip.ipv4(a,b,c,d),Some{port}),ticket_routes(rest))
    case Con{Tickets.IPv6{ip,port},rest}:
      add_ip(ip_port(String.from_list(Ip.ipv6_chars(ip)),Some{port}),ticket_routes(rest))
    case Con{Tickets.Relay{url},rest}:
      add_relay(relay_url(url),ticket_routes(rest))
    case Con{_,rest}:
      ticket_routes(rest)

def ticket_action(-C: Type, ticket: Maybe<&2,Tickets.EndpointTicket>, seed: List<&2,U32>, alpn: List<&2,U32>,
    action: Routes -> Identity -> IO(Result<&1,&1,U32 & String,C>)) -> IO(Result<&1,&1,U32 & String,C>):
  match ticket:
    case Some{Tickets.Ticket{peer,addresses}}:
      action(ticket_routes(addresses),PeerKeys{seed,peer,alpn})
    case None{}:
      IO.pure(Result<&1,&1,U32 & String,C>,Fail{(1,"invalid endpoint ticket")})

def use_ticket(~C: Type, ~dial: Routes -> Identity -> Timeouts -> IO(Result<&1,&1,U32 & String,C>),
    ticket: Maybe<&2,Tickets.EndpointTicket>, seed: List<&2,U32>, alpn: List<&2,U32>, timeouts: Timeouts)
    -> IO(Result<&1,&1,U32 & String,C>):
  ticket_action(C,ticket,seed,alpn,plan => identity => dial(plan,identity,timeouts))

def with_ticket(~C: Type, ~dial: Routes -> Identity -> Timeouts -> IO(Result<&1,&1,U32 & String,C>),
    text: String, seed: List<&2,U32>, alpn: List<&2,U32>, timeouts: Timeouts)
    -> IO(Result<&1,&1,U32 & String,C>):
  do IO<Result<&1,&1,U32 & String,C>>:
    ticket : Maybe<&2,Tickets.EndpointTicket> <- Tickets.decode(text)
    use_ticket(~C,~dial,ticket,seed,alpn,timeouts)

def remote_options(same_endpoint: Bool, alpn: List<&2,U32>) -> Result<&1,&1,U32 & String,Unit>:
  match same_endpoint alpn:
    case True{} _:
      Fail{(22,"Connecting to ourself is not supported")}
    case False{} Nil{}:
      Fail{(22,"Invalid ALPN")}
    case False{} _:
      Done{Unit{}}

def remote_key(local: Result<&1,&1,U32 & String,List<&2,U32>>, peer: List<&2,U32>, alpn: List<&2,U32>)
    -> Result<&1,&1,U32 & String,Unit>:
  match local:
    case Done{key}:
      remote_options(Dns.bytes_eq(key,peer),alpn)
    case Fail{error}:
      Fail{error}

def start_checked(-C: Type, checked: Result<&1,&1,U32 & String,Unit>,
    start: Unit -> IO(Result<&1,&1,U32 & String,C>)) -> IO(Result<&1,&1,U32 & String,C>):
  match checked:
    case Done{_}:
      start(Unit{})
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,C>,Fail{error})

def before_connect(-C: Type, identity: Identity, start: Unit -> IO(Result<&1,&1,U32 & String,C>))
    -> IO(Result<&1,&1,U32 & String,C>):
  PeerKeys{seed,peer,alpn} = identity
  do IO<Result<&1,&1,U32 & String,C>>:
    local : Result<&1,&1,U32 & String,List<&2,U32>> <- Ed.public_key(seed)
    start_checked(C,remote_key(local,peer,alpn),start)

def direct_stream(address: Address, identity: Identity, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Direct.QuicConnection>):
  IpAddress{host,port} = address
  PeerKeys{seed,peer,alpn} = identity
  Direct.quic_connect_with_timeout(host,port,seed,peer,alpn,ms)

def direct_quic(address: Address, identity: Identity, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Quic.DatagramConnection>):
  IpAddress{host,port} = address
  PeerKeys{seed,peer,alpn} = identity
  Quic.connect(host,port,seed,peer,alpn,U32.to_nat(ms))

def attach_connection(-C: Type, outcome: Result<&1,&1,U32 & String,C>, bridge: Path.Bridge)
    -> IO(TransportResult(C)):
  match outcome:
    case Done{conn}:
      IO.pure(TransportResult(C),Done{(conn,Some{bridge})})
    case Fail{error}:
      do IO<TransportResult(C)>:
        _ : Result<&1,&1,U32 & String,Unit> <- Path.stop(bridge)
        return Fail{error}

def connect_bridge(~C: Type, ~attempt: Dialer(C), outcome: Result<&1,&1,U32 & String,Path.Bridge & U32>,
    identity: Identity, ms: U32) -> IO(TransportResult(C)):
  match outcome:
    case Done{(bridge,port)}:
      do IO<TransportResult(C)>:
        result : Result<&1,&1,U32 & String,C> <- attempt(IpAddress{"127.0.0.1",port},identity,ms)
        attach_connection(C,result,bridge)
    case Fail{error}:
      IO.pure(TransportResult(C),Fail{error})

def try_relay(~C: Type, ~attempt: Dialer(C), url: String, +identity: Identity, ms: U32) -> IO(TransportResult(C)):
  PeerKeys{seed,peer,_} = identity
  do IO<TransportResult(C)>:
    path : Result<&1,&1,U32 & String,Path.Bridge & U32> <- Path.start(url,seed,peer,0)
    connect_bridge(~C,~attempt,path,identity,ms)

def continue_dial(-C: Type, outcome: TransportResult(C), next: (U32 & String) -> IO(TransportResult(C)))
    -> IO(TransportResult(C)):
  match outcome:
    case Done{conn}:
      IO.pure(TransportResult(C),Done{conn})
    case Fail{error}:
      next(error)

def try_relays(~C: Type, ~attempt: Dialer(C), urls: List<&2,String>, +identity: Identity, +ms: U32,
    last: U32 & String) -> IO(TransportResult(C)):
  match urls:
    case Nil{}:
      IO.pure(TransportResult(C),Fail{last})
    case Con{url,rest}:
      do IO<TransportResult(C)>:
        outcome : TransportResult(C) <- try_relay(~C,~attempt,url,identity,ms)
        continue_dial(C,outcome,error => try_relays(~C,~attempt,rest,identity,ms,error))

def direct_timeout(timeouts: Timeouts) -> U32:
  HandshakeTimeouts{ms,_} = timeouts
  ms

def try_ips(~C: Type, ~attempt: Dialer(C), ~relay_attempt: Dialer(C), ips: List<&2,Address>, urls: List<&2,String>, +identity: Identity,
    +timeouts: Timeouts, last: U32 & String) -> IO(TransportResult(C)):
  match ips:
    case Nil{}:
      HandshakeTimeouts{_,relay_ms} = timeouts
      try_relays(~C,~relay_attempt,urls,identity,relay_ms,last)
    case Con{ip,rest}:
      do IO<TransportResult(C)>:
        conn : Result<&1,&1,U32 & String,C> <- attempt(ip,identity,direct_timeout(timeouts))
        continue_dial(C,Result.map(&1,&1,U32 & String,C,Transport(C),c => (c,None{}),conn),
          error => try_ips(~C,~attempt,~relay_attempt,rest,urls,identity,timeouts,error))

def dial_validated_plan(~C: Type, ~direct: Dialer(C), ~relay: Dialer(C), plan: Routes, identity: Identity, timeouts: Timeouts)
    -> IO(TransportResult(C)):
  DialRoutes{ips,urls} = plan
  try_ips(~C,~direct,~relay,ips,urls,identity,timeouts,(1,"endpoint has no usable direct address or relay"))

def dial_plan_with(~C: Type, ~direct: Dialer(C), ~relay: Dialer(C), plan: Routes, +identity: Identity, timeouts: Timeouts)
    -> IO(TransportResult(C)):
  before_connect(Transport(C),identity,u => dial_validated_plan(~C,~direct,~relay,plan,identity,timeouts))

def dial_plan(~C: Type, ~attempt: Dialer(C), plan: Routes, identity: Identity, timeouts: Timeouts)
    -> IO(TransportResult(C)):
  dial_plan_with(~C,~attempt,~attempt,plan,identity,timeouts)

def dial_routes(plan: Routes, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  dial_plan(~Direct.QuicConnection,~direct_stream,plan,identity,timeouts)

def dial(records: List<&2,Dns.Attribute>, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  dial_routes(routes(records),identity,timeouts)

def dns_records(reply: Result<&1,&1,U32 & String,Dns.Reply>) -> Result<&1,&1,U32 & String,List<&2,Dns.Attribute>>:
  match reply:
    case Done{Dns.Found{records}}:
      Done{records}
    case Done{Dns.DnsError{code}}:
      Fail{(code,"endpoint DNS lookup returned an error")}
    case Done{_}:
      Fail{(1,"endpoint DNS lookup did not return usable records")}
    case Fail{error}:
      Fail{error}

def planned_records(records: Result<&1,&1,U32 & String,List<&2,Dns.Attribute>>) -> Result<&1,&1,U32 & String,Routes>:
  Result.map(&1,&1,U32 & String,List<&2,Dns.Attribute>,Routes,routes,records)

def dns_routes(reply: Result<&1,&1,U32 & String,Dns.Reply>) -> Result<&1,&1,U32 & String,Routes>:
  planned_records(dns_records(reply))

def lookup_routes(identity: Identity, resolver: DnsSource) -> IO(Result<&1,&1,U32 & String,Routes>):
  PeerKeys{_,key,_} = identity
  DnsResolver{origin,host,port,ms} = resolver
  do IO<Result<&1,&1,U32 & String,Routes>>:
    reply : Result<&1,&1,U32 & String,Dns.Reply> <- Dns.lookup(key,origin,host,port,ms)
    return dns_routes(reply)

def verified_records(verified: Pkarr.Verification) -> Result<&1,&1,U32 & String,List<&2,Dns.Attribute>>:
  match verified:
    case Pkarr.Verified{_,records}:
      Done{records}
    case _:
      Fail{(1,"invalid signed Pkarr endpoint packet")}

def pkarr_routes(verified: Pkarr.Verification) -> Result<&1,&1,U32 & String,Routes>:
  planned_records(verified_records(verified))

def verify_routes(identity: Identity, packet: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,Routes>):
  PeerKeys{_,key,_} = identity
  do IO<Result<&1,&1,U32 & String,Routes>>:
    verified : Pkarr.Verification <- Pkarr.verify(key,packet)
    return pkarr_routes(verified)

def dial_resolved(~C: Type, ~attempt: Dialer(C), planned: Result<&1,&1,U32 & String,Routes>,
    identity: Identity, timeouts: Timeouts) -> IO(TransportResult(C)):
  match planned:
    case Done{plan}:
      dial_validated_plan(~C,~attempt,~attempt,plan,identity,timeouts)
    case Fail{error}:
      IO.pure(TransportResult(C),Fail{error})

def connect_resolved(~C: Type, ~attempt: Dialer(C), planned: Result<&1,&1,U32 & String,Routes>,
    +identity: Identity, timeouts: Timeouts) -> IO(TransportResult(C)):
  before_connect(Transport(C),identity,u => dial_resolved(~C,~attempt,planned,identity,timeouts))

def resolve_and_connect(~C: Type, ~attempt: Dialer(C), +identity: Identity, timeouts: Timeouts,
    resolve: Identity -> IO(Result<&1,&1,U32 & String,Routes>)) -> IO(TransportResult(C)):
  before_connect(Transport(C),identity,u =>
    do IO<TransportResult(C)>:
      plan : Result<&1,&1,U32 & String,Routes> <- resolve(identity)
      dial_resolved(~C,~attempt,plan,identity,timeouts))

def pkarr_reply(reply: Result<&1,&1,U32 & String,Pkarr.Verification>) -> Result<&1,&1,U32 & String,Routes>:
  match reply:
    case Done{proof}:
      pkarr_routes(proof)
    case Fail{error}:
      Fail{error}

def resolve_source(source: AddressLookup, identity: Identity) -> IO(Result<&1,&1,U32 & String,Routes>):
  match source:
    case DnsLookup{resolver}:
      lookup_routes(identity,resolver)
    case PkarrLookup{relay,ms}:
      PeerKeys{_,key,_} = identity
      do IO<Result<&1,&1,U32 & String,Routes>>:
        proof : Result<&1,&1,U32 & String,Pkarr.Verification> <- PkarrHttp.resolve(relay,key,ms)
        return pkarr_reply(proof)

type LookupItem is Data:
  LookupItem{endpoint_id: List<&2,U32>, source: AddressLookup, records: List<&2,Dns.Attribute>}

type LookupError is Data:
  LookupError{source: AddressLookup, code: U32, message: String}

type LookupAnswer is Data:
  FoundItem{item: LookupItem}
  SourceError{error: LookupError}

type LookupEvent is Data:
  ServiceResult{answer: LookupAnswer}
  NoServiceConfigured{}
  NoResults{errors: List<&2,LookupError>}
  LookupEnd{}

type LookupStream is Type:
  NoServices{}
  Resolving{remaining: Nat, replies: Chan(LookupAnswer), stop: Chan(Unit), yielded: Bool, errors: List<&2,LookupError>}
  FinishedLookup{}

def lookup_answer(reply: Result<&1,&1,U32 & String,List<&2,Dns.Attribute>>, source: AddressLookup, key: List<&2,U32>)
    -> LookupAnswer:
  match reply:
    case Done{records}:
      FoundItem{LookupItem{key,source,records}}
    case Fail{(code,message)}:
      SourceError{LookupError{source,code,message}}

def pkarr_item(proof: PkarrHttp.Proof(), source: AddressLookup, key: List<&2,U32>) -> LookupAnswer:
  match proof:
    case Done{verified}:
      lookup_answer(verified_records(verified),source,key)
    case Fail{(code,message)}:
      SourceError{LookupError{source,code,message}}

def resolve_until(+source: AddressLookup, +key: List<&2,U32>, +stop: Chan(Unit)) -> IO(LookupAnswer):
  match source:
    case DnsLookup{DnsResolver{origin,host,port,ms}}:
      do IO<LookupAnswer>:
        id : Result<&1,&1,U32 & String,U32> <- IO.random_u32()
        reply : Result<&1,&1,U32 & String,Dns.Reply> <- Dns.lookup_using(id,key,origin,host,port,ms,
          Dns.StopOnClose{stop},name => p => timeout => LookupSocket.connect(stop,name,p,timeout))
        return lookup_answer(dns_records(reply),source,key)
    case PkarrLookup{url,ms}:
      do IO<LookupAnswer>:
        proof : PkarrHttp.Proof() <- PkarrHttp.resolve_until(url,key,ms,stop)
        return pkarr_item(proof,source,key)

def publish_lookup(source: AddressLookup, key: List<&2,U32>, results: Chan(LookupAnswer), stop: Chan(Unit)) -> IO(Unit):
  do IO<Unit>:
    answer : LookupAnswer <- resolve_until(source,key,stop)
    _ : Result<&1,&1,LookupAnswer,Unit> <- Chan.send(LookupAnswer,results,answer)
    return Unit{}

def spawn_lookups(sources: List<&2,AddressLookup>, +key: List<&2,U32>, +results: Chan(LookupAnswer),
    +stop: Chan(Unit)) -> IO(Unit):
  match sources:
    case Nil{}:
      IO.pure(Unit,Unit{})
    case Con{source,rest}:
      do IO<Unit>:
        IO.spawn(Unit,publish_lookup(source,key,results,stop))
        spawn_lookups(rest,key,results,stop)

def resolve_addresses(+sources: List<&2,AddressLookup>, key: List<&2,U32>) -> IO(LookupStream):
  match sources:
    case Nil{}:
      IO.pure(LookupStream,NoServices{})
    case Con{_,_}:
      +count = List.length(&2,AddressLookup,sources)
      do IO<LookupStream>:
        +results : Chan(LookupAnswer) <- Chan.new(LookupAnswer,U32.from_nat(count))
        +stop : Chan(Unit) <- Chan.new(Unit,0)
        spawn_lookups(sources,key,results,stop)
        return Resolving{count,results,stop,False{},[]}

def drain_lookups(remaining: Nat, +results: Chan(LookupAnswer)) -> IO(Unit):
  match remaining:
    case 0n:
      Chan.close(LookupAnswer,results)
    case 1n+k:
      do IO<Unit>:
        _ : Maybe<&1,LookupAnswer> <- Chan.recv(LookupAnswer,results)
        drain_lookups(k,results)

def close_lookup(stream: LookupStream) -> IO(Unit):
  match stream:
    case Resolving{count,results,stop,_,_}:
      do IO<Unit>:
        Chan.close(Unit,stop)
        drain_lookups(count,results)
    case _:
      IO.pure(Unit,Unit{})

def terminal_lookup(yielded: Bool, errors: List<&2,LookupError>) -> LookupEvent:
  match yielded:
    case True{}:
      LookupEnd{}
    case False{}:
      NoResults{List.reverse(&2,LookupError,errors)}

def received_lookup(answer: Maybe<&1,LookupAnswer>, left: Nat, results: Chan(LookupAnswer), stop: Chan(Unit),
    yielded: Bool, errors: List<&2,LookupError>) -> LookupStream & LookupEvent:
  match answer:
    case Some{FoundItem{item}}:
      (Resolving{left,results,stop,True{},errors},ServiceResult{FoundItem{item}})
    case Some{SourceError{+error}}:
      (Resolving{left,results,stop,yielded,Con{error,errors}},ServiceResult{SourceError{error}})
    case None{}:
      (FinishedLookup{},terminal_lookup(yielded,errors))

def next_lookup(stream: LookupStream) -> IO(LookupStream & LookupEvent):
  match stream:
    case NoServices{}:
      IO.pure(LookupStream & LookupEvent,(FinishedLookup{},NoServiceConfigured{}))
    case FinishedLookup{}:
      IO.pure(LookupStream & LookupEvent,(FinishedLookup{},LookupEnd{}))
    case Resolving{0n,results,stop,yielded,errors}:
      do IO<LookupStream & LookupEvent>:
        Chan.close(Unit,stop)
        Chan.close(LookupAnswer,results)
        return (FinishedLookup{},terminal_lookup(yielded,errors))
    case Resolving{1n+k,+results,stop,yielded,errors}:
      do IO<LookupStream & LookupEvent>:
        answer : Maybe<&1,LookupAnswer> <- Chan.recv(LookupAnswer,results)
        return received_lookup(answer,k,results,stop,yielded,errors)

def error_messages(errors: List<&2,LookupError>) -> String:
  match errors:
    case Nil{}:
      ""
    case Con{LookupError{_,_,message},rest}:
      " / " ++ (message ++ error_messages(rest))

def lookup_failure(errors: List<&2,LookupError>, last: U32 & String) -> U32 & String:
  match errors:
    case Nil{}:
      last
    case Con{LookupError{_,code,message},rest}:
      (code,message ++ error_messages(rest))

def use_lookup_connection(outcome: ConnectResult(), stream: LookupStream,
    again: LookupStream -> (U32 & String) -> IO(ConnectResult())) -> IO(ConnectResult()):
  match outcome:
    case Done{conn}:
      do IO<ConnectResult()>:
        close_lookup(stream)
        return Done{conn}
    case Fail{error}:
      again(stream,error)

def dial_lookup_event(step: LookupStream & LookupEvent, last: U32 & String, identity: Identity, timeouts: Timeouts,
    again: LookupStream -> (U32 & String) -> IO(ConnectResult())) -> IO(ConnectResult()):
  match step:
    case (stream,ServiceResult{FoundItem{LookupItem{_,_,records}}}):
      do IO<ConnectResult()>:
        outcome : ConnectResult() <- dial_validated_plan(~Quic.DatagramConnection,~direct_quic,~direct_quic,
          routes(records),identity,timeouts)
        use_lookup_connection(outcome,stream,again)
    case (stream,ServiceResult{SourceError{_}}):
      again(stream,last)
    case (_,NoResults{errors}):
      IO.pure(ConnectResult(),Fail{lookup_failure(errors,last)})
    case _:
      IO.pure(ConnectResult(),Fail{last})

@unsafe def dial_lookup_stream(stream: LookupStream, last: U32 & String, +identity: Identity,
    +timeouts: Timeouts) -> IO(ConnectResult()):
  do IO<ConnectResult()>:
    step : LookupStream & LookupEvent <- next_lookup(stream)
    dial_lookup_event(step,last,identity,timeouts,next => reason => dial_lookup_stream(next,reason,identity,timeouts))

def try_lookups(sources: List<&2,AddressLookup>, outcome: ConnectResult(), +identity: Identity,
    timeouts: Timeouts) -> IO(ConnectResult()):
  match outcome:
    case Fail{error}:
      PeerKeys{_,key,_} = identity
      do IO<ConnectResult()>:
        stream : LookupStream <- resolve_addresses(sources,key)
        dial_lookup_stream(stream,error,identity,timeouts)
    case Done{conn}:
      IO.pure(ConnectResult(),Done{conn})

type DialProgress is Data:
  DialProgress{pending: Nat, opening: List<&2,String>, yielded: Bool, errors: List<&2,LookupError>}

type DialContext is Data:
  DialContext{identity: Identity, timeouts: Timeouts, idle_ms: NatWire.VarInt, workers: Dial.Workers<LookupAnswer>}

def Attempts(-C: Type) -> Type:
  Race.State<C> & DialProgress

def ResumeDial(-C: Type) -> Type:
  Attempts(C) -> IO(TransportResult(C))

def observe_sources(sources: List<&2,AddressLookup>, +key: List<&2,U32>, +workers: Dial.Workers<LookupAnswer>) -> IO(Unit):
  match sources:
    case Nil{}:
      IO.pure(Unit,Unit{})
    case Con{source,rest}:
      do IO<Unit>:
        IO.spawn(Unit,Dial.lookup(~LookupAnswer,stop => resolve_until(source,key,stop),workers))
        observe_sources(rest,key,workers)

def same_ip(left: Address, right: Address) -> Bool:
  IpAddress{a,p} = left
  IpAddress{b,q} = right
  U32.is_eq(p,q) && String.eq(a,b)

def add_direct(~C: Type, ~engine: Race.Backend<C>, ~launch: Race.Starter(C), +idle_ms: NatWire.VarInt, ips: List<&2,Address>, state: Race.State<C>, +identity: Identity, +deadline: Nat) -> IO(Race.State<C>):
  match ips:
    case Nil{}:
      IO.pure(Race.State<C>,state)
    case Con{IpAddress{host,port},tail}:
      PeerKeys{seed,peer,alpn} = identity
      do IO<Race.State<C>>:
        next : Race.State<C> <- Race.add_using(~C,~engine,~launch,idle_ms,state,host,port,deadline,None{},seed,peer,alpn)
        add_direct(~C,~engine,~launch,idle_ms,tail,next,identity,deadline)

def start_relay_candidates(identity: Identity, urls: List<&2,String>, events: Chan(Dial.DialEvent<LookupAnswer>)) -> IO(Unit):
  PeerKeys{seed,peer,_} = identity
  Dial.start_relays(~LookupAnswer,urls,seed,peer,events)

def known_routes(keys: List<&2,Race.RouteKey>, opening: List<&2,String>) -> Routes:
  match keys:
    case Nil{}:
      DialRoutes{[],opening}
    case Con{Race.DirectKey{host,port},rest}:
      add_ip(Some{IpAddress{host,port}},known_routes(rest,opening))
    case Con{Race.RelayKey{url},rest}:
      add_relay(Some{url},known_routes(rest,opening))

def schedule_candidates(~C: Type, ~engine: Race.Backend<C>, ~launch: Race.Starter(C), plan: Routes, known: Routes, state: Race.State<C>, progress: DialProgress, context: DialContext) -> IO(Attempts(C)):
  DialRoutes{ips,urls} = plan
  DialRoutes{known_ips,known_urls} = known
  DialProgress{pending,opening,yielded,errors} = progress
  DialContext{+identity,timeouts,idle_ms,Dial.Workers{events,_,_,_}} = context
  added_ips = Dial.fresh(~Address,~same_ip,ips,known_ips)
  +added_urls = Dial.fresh(~String,~String.eq,urls,known_urls)
  count = Nat.add(pending,List.length(&2,String,added_urls))
  do IO<Attempts(C)>:
    now : Nat <- IO.now()
    started : Race.State<C> <- add_direct(~C,~engine,~launch,idle_ms,added_ips,state,identity,Nat.add(now,U32.to_nat(direct_timeout(timeouts))))
    start_relay_candidates(identity,added_urls,events)
    return (started,DialProgress{count,List.append(&2,String,added_urls,opening),yielded,errors})

def schedule_discovery(~C: Type, ~engine: Race.Backend<C>, ~launch: Race.Starter(C), catalog: Race.Catalog(C), plan: Routes, progress: DialProgress, context: DialContext) -> IO(Attempts(C)):
  (state,keys) = catalog
  DialProgress{pending,+opening,yielded,errors} = progress
  schedule_candidates(~C,~engine,~launch,plan,known_routes(keys,opening),state,DialProgress{pending,opening,yielded,errors},context)

def add_candidates(~C: Type, ~engine: Race.Backend<C>, ~launch: Race.Starter(C), plan: Routes, state: Race.State<C>, progress: DialProgress, context: DialContext) -> IO(Attempts(C)):
  schedule_discovery(~C,~engine,~launch,Race.catalog(C,state),plan,progress,context)

def remove_opening(+url: String, opening: List<&2,String>) -> List<&2,String>:
  match opening:
    case Nil{}:
      []
    case Con{+head,+tail}:
      Bool.pick(List<&2,String>,String.eq(url,head),tail,Con{head,remove_opening(url,tail)})

def race_error(-C: Type, state: Race.State<C>, reason: U32 & String) -> Race.State<C>:
  match state:
    case Race.Waiting{_}:
      Race.Waiting{reason}
    case Race.Racing{conn,paths,flight,collecting,_}:
      Race.Racing{conn,paths,flight,collecting,reason}
    case _:
      state

def relay_offer(~C: Type, ~engine: Race.Backend<C>, ~launch: Race.Starter(C), offer: Dial.Offer(), state: Race.State<C>, context: DialContext) -> IO(Race.State<C>):
  match offer:
    case Fail{error}:
      IO.pure(Race.State<C>,race_error(C,state,error))
    case Done{(bridge,port)}:
      DialContext{PeerKeys{seed,peer,alpn},HandshakeTimeouts{_,ms},idle_ms,_} = context
      do IO<Race.State<C>>:
        now : Nat <- IO.now()
        Race.add_using(~C,~engine,~launch,idle_ms,state,"127.0.0.1",port,Nat.add(now,U32.to_nat(ms)),Some{bridge},seed,peer,alpn)

def dial_event(~C: Type, ~engine: Race.Backend<C>, ~launch: Race.Starter(C), event: Dial.DialEvent<LookupAnswer>, state: Race.State<C>, progress: DialProgress,
    context: DialContext, resume: ResumeDial(C)) -> IO(TransportResult(C)):
  match event:
    case Dial.Lookup{FoundItem{LookupItem{_,_,records}}}:
      DialProgress{pending,opening,_,errors} = progress
      do IO<TransportResult(C)>:
        next : Attempts(C) <- add_candidates(~C,~engine,~launch,routes(records),state,DialProgress{Nat.sub(pending,1n),opening,True{},errors},context)
        resume(next)
    case Dial.Lookup{SourceError{error}}:
      DialProgress{pending,opening,yielded,errors} = progress
      resume((state,DialProgress{Nat.sub(pending,1n),opening,yielded,Con{error,errors}}))
    case Dial.Relay{url,offer}:
      DialProgress{pending,opening,yielded,errors} = progress
      do IO<TransportResult(C)>:
        next : Race.State<C> <- relay_offer(~C,~engine,~launch,offer,state,context)
        resume((next,DialProgress{Nat.sub(pending,1n),remove_opening(url,opening),yielded,errors}))

def dial_poll(~C: Type, ~engine: Race.Backend<C>, ~launch: Race.Starter(C), event: Poll<&1,&1,Maybe<&1,Dial.DialEvent<LookupAnswer>>,Unit>, state: Race.State<C>,
    progress: DialProgress, context: DialContext, resume: ResumeDial(C)) -> IO(TransportResult(C)):
  match event:
    case Ready{Some{item}}:
      dial_event(~C,~engine,~launch,item,state,progress,context,resume)
    case _:
      resume((state,progress))

def terminal_dial(yielded: Bool, errors: List<&2,LookupError>, last: U32 & String) -> U32 & String:
  match yielded:
    case True{}:
      last
    case False{}:
      lookup_failure(List.reverse(&2,LookupError,errors),last)

def await_candidate(~C: Type, ~engine: Race.Backend<C>, ~launch: Race.Starter(C), reason: U32 & String, progress: DialProgress, +context: DialContext, resume: ResumeDial(C)) -> IO(TransportResult(C)):
  match progress:
    case DialProgress{0n,_,yielded,errors}:
      DialContext{_,_,_,workers} = context
      do IO<TransportResult(C)>:
        Dial.close(~LookupAnswer,workers)
        return Fail{terminal_dial(yielded,errors,reason)}
    case DialProgress{1n+k,opening,yielded,errors}:
      DialContext{_,_,_,Dial.Workers{events,_,_,_}} = context
      do IO<TransportResult(C)>:
        event : Maybe<&1,Dial.DialEvent<LookupAnswer>> <- Chan.recv(Dial.DialEvent<LookupAnswer>,events)
        dial_poll(~C,~engine,~launch,Ready{event},Race.Waiting{reason},DialProgress{1n+k,opening,yielded,errors},context,resume)

def progress_dial(~C: Type, ~engine: Race.Backend<C>, ~launch: Race.Starter(C), state: Race.State<C>, progress: DialProgress, +context: DialContext, resume: ResumeDial(C)) -> IO(TransportResult(C)):
  match state:
    case Race.Connected{conn,bridge}:
      DialContext{_,_,_,workers} = context
      do IO<TransportResult(C)>:
        Dial.close(~LookupAnswer,workers)
        return Done{(conn,bridge)}
    case Race.Waiting{last}:
      await_candidate(~C,~engine,~launch,last,progress,context,resume)
    case Race.Racing{conn,routes,flight,collecting,last}:
      DialContext{_,_,_,Dial.Workers{events,_,_,_}} = context
      do IO<TransportResult(C)>:
        event : Poll<&1,&1,Maybe<&1,Dial.DialEvent<LookupAnswer>>,Unit> <- Chan.try_recv(Dial.DialEvent<LookupAnswer>,events,1)
        dial_poll(~C,~engine,~launch,event,Race.Racing{conn,routes,flight,collecting,last},progress,context,resume)

@unsafe def drive_dial(~C: Type, ~engine: Race.Backend<C>, ~launch: Race.Starter(C), attempts: Attempts(C), +context: DialContext) -> IO(TransportResult(C)):
  (state,progress) = attempts
  do IO<TransportResult(C)>:
    next : Race.State<C> <- Race.step(~C,~engine,state)
    progress_dial(~C,~engine,~launch,next,progress,context,more => drive_dial(~C,~engine,~launch,more,context))

def start_dial_using(~C: Type, ~engine: Race.Backend<C>, ~launch: Race.Starter(C), +idle_ms: NatWire.VarInt, plan: Routes, +identity: Identity, +timeouts: Timeouts, +sources: List<&2,AddressLookup>) -> IO(TransportResult(C)):
  PeerKeys{_,key,_} = identity
  +count = List.length(&2,AddressLookup,sources)
  do IO<TransportResult(C)>:
    +workers : Dial.Workers<LookupAnswer> <- Dial.create(~LookupAnswer,count)
    observe_sources(sources,key,workers)
    state : Attempts(C) <- add_candidates(~C,~engine,~launch,plan,Race.Waiting{(1,"endpoint has no usable direct address or relay")},
      DialProgress{count,[],False{},[]},DialContext{identity,timeouts,idle_ms,workers})
    drive_dial(~C,~engine,~launch,state,DialContext{identity,timeouts,idle_ms,workers})

def start_dial_with(~C: Type, ~engine: Race.Backend<C>, plan: Routes, +identity: Identity, +timeouts: Timeouts, +sources: List<&2,AddressLookup>) -> IO(TransportResult(C)):
  start_dial_using(~C,~engine,~(h => p => s => key => a => ms => Race.begin(C,engine,h,p,s,key,a)),Close.default_idle_timeout(),plan,identity,timeouts,sources)

def shared_handshake() -> Race.Backend<Quic.DatagramConnection>:
  Race.Backend{Quic.start_route_handshake,Quic.open_handshake_socket,Quic.read_handshake_socket,
    Quic.route_handshake_output,Quic.adopt_handshake_socket,Quic.drop_quic_datagram,"QUIC datagram handshake timed out"}

def start_lookup_dial(plan: Routes, identity: Identity, timeouts: Timeouts, sources: List<&2,AddressLookup>) -> IO(ConnectResult()):
  start_dial_using(~Quic.DatagramConnection,~shared_handshake(),~Quic.start_route_handshake_with_idle_timeout,
    Close.default_idle_timeout(),plan,identity,timeouts,sources)

def connect_with_lookup_and_idle_timeout(plan: Routes, +identity: Identity, timeouts: Timeouts,
    sources: List<&2,AddressLookup>, idle_ms: NatWire.VarInt) -> IO(ConnectResult()):
  before_connect(Connection(),identity,u => start_dial_using(~Quic.DatagramConnection,~shared_handshake(),
    ~Quic.start_route_handshake_with_idle_timeout,idle_ms,plan,identity,timeouts,sources))

def connect_routes_with_idle_timeout(plan: Routes, identity: Identity, timeouts: Timeouts,
    idle_ms: NatWire.VarInt) -> IO(ConnectResult()):
  connect_with_lookup_and_idle_timeout(plan,identity,timeouts,[],idle_ms)

def connect_with_lookup(plan: Routes, +identity: Identity, timeouts: Timeouts, sources: List<&2,AddressLookup>)
    -> IO(ConnectResult()):
  before_connect(Connection(),identity,u => start_lookup_dial(plan,identity,timeouts,sources))

# Dial the supplied transports with one pinned QUIC connection. The returned
# connection exposes both streams and application datagrams.
def connect_routes(plan: Routes, identity: Identity, timeouts: Timeouts) -> IO(ConnectResult()):
  connect_with_lookup(plan,identity,timeouts,[])

def connect_ticket(text: String, seed: List<&2,U32>, alpn: List<&2,U32>, timeouts: Timeouts) -> IO(ConnectResult()):
  with_ticket(~Connection(),~connect_routes,text,seed,alpn,timeouts)

def connect(records: List<&2,Dns.Attribute>, identity: Identity, timeouts: Timeouts) -> IO(ConnectResult()):
  connect_routes(routes(records),identity,timeouts)

def connect_ticket_with_lookup(text: String, seed: List<&2,U32>, alpn: List<&2,U32>, timeouts: Timeouts,
    sources: List<&2,AddressLookup>) -> IO(ConnectResult()):
  do IO<ConnectResult()>:
    ticket : Maybe<&2,Tickets.EndpointTicket> <- Tickets.decode(text)
    ticket_action(Connection(),ticket,seed,alpn,plan => identity => connect_with_lookup(plan,identity,timeouts,sources))

def from_dns(reply: Result<&1,&1,U32 & String,Dns.Reply>, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  connect_resolved(~Direct.QuicConnection,~direct_stream,dns_routes(reply),identity,timeouts)

def lookup_and_dial(+identity: Identity, resolver: DnsSource, timeouts: Timeouts) -> IO(Outcome()):
  resolve_and_connect(~Direct.QuicConnection,~direct_stream,identity,timeouts,key => lookup_routes(key,resolver))

def from_pkarr(verified: Pkarr.Verification, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  connect_resolved(~Direct.QuicConnection,~direct_stream,pkarr_routes(verified),identity,timeouts)

def verify_and_dial(+identity: Identity, packet: List<&2,U32>, timeouts: Timeouts) -> IO(Outcome()):
  resolve_and_connect(~Direct.QuicConnection,~direct_stream,identity,timeouts,key => verify_routes(key,packet))

def lookup_and_connect(+identity: Identity, resolver: DnsSource, timeouts: Timeouts) -> IO(ConnectResult()):
  connect_with_lookup(DialRoutes{[],[]},identity,timeouts,[DnsLookup{resolver}])

def dial_verified(result: Result<&1,&1,U32 & String,Routes>, identity: Identity, timeouts: Timeouts) -> IO(ConnectResult()):
  match result:
    case Fail{error}:
      IO.pure(ConnectResult(),Fail{error})
    case Done{plan}:
      start_lookup_dial(plan,identity,timeouts,[])

def verify_and_connect(+identity: Identity, packet: List<&2,U32>, timeouts: Timeouts) -> IO(ConnectResult()):
  before_connect(Connection(),identity,u =>
    do IO<ConnectResult()>:
      result : Result<&1,&1,U32 & String,Routes> <- verify_routes(identity,packet)
      dial_verified(result,identity,timeouts))

def keep_path(-R: Type, outcome: Quic.DatagramConnection & R, path: Maybe<&1,Path.Bridge>) -> Connection() & R:
  (conn,value) = outcome
  ((conn,path),value)

# Run a transport operation while retaining ownership of the selected path.
def use_connection(-R: Type, connected: Connection(), operation: Quic.DatagramConnection -> IO(Quic.DatagramConnection & R))
    -> IO(Connection() & R):
  (conn,path) = connected
  do IO<Connection() & R>:
    outcome : Quic.DatagramConnection & R <- operation(conn)
    return keep_path(R,outcome,path)

# Probe a new route while retaining ownership of the existing relay bridge, if present.
def start_path_migration(connected: Connection(), local: Address, remote: Address)
    -> IO(Connection() & Result<&1,&1,U32 & String,U32>):
  IpAddress{host,port} = local
  IpAddress{peer,peer_port} = remote
  use_connection(Result<&1,&1,U32 & String,U32>,connected,
    conn => Quic.start_quic_path_migration(conn,host,port,peer,peer_port))

def close_with(connection: Connection(), code: NatWire.VarInt, reason: List<&2,U32>)
    -> IO(Connection() & Close.WriteResult()):
  use_connection(Close.WriteResult(),connection,c => Quic.close_quic_connection(c,code,reason))

def close_reason(connection: Connection()) -> IO(Connection() & Close.ReadResult()):
  use_connection(Close.ReadResult(),connection,Quic.quic_close_reason)

def disconnect(connected: Connection()) -> IO(Result<&1,&1,U32 & String,Unit>):
  match connected:
    case (conn,None{}):
      do IO<Result<&1,&1,U32 & String,Unit>>:
        Quic.drop_quic_datagram(conn)
        return Done{Unit{}}
    case (conn,Some{path}):
      do IO<Result<&1,&1,U32 & String,Unit>>:
        Quic.drop_quic_datagram(conn)
        Path.stop(path)

type RecoveryPlan is Data:
  RelayFallback{identity: Identity, urls: List<&2,String>, direct: List<&2,Address>, probe_ms: U32}

type RecoveryState is Data:
  DirectOnly{}
  Watching{plan: RecoveryPlan}
  DialingRelay{plan: RecoveryPlan, remaining: List<&2,String>}
  ProbingRelay{plan: RecoveryPlan, remaining: List<&2,String>, port: U32, since: U32}
  ValidatingRelay{plan: RecoveryPlan, remaining: List<&2,String>}
  OnRelay{}
  SeekingDirect{plan: RecoveryPlan, remaining: List<&2,Address>, since: U32}
  ValidatingDirect{plan: RecoveryPlan, remaining: List<&2,Address>}

type RoutedConnection is Type:
  Routed{transport: Connection(), recovery: RecoveryState}

type SelectedRoute is Data:
  DirectRoute{}
  RelayRoute{}

def RoutedResult() -> Type:
  Result<&1,&1,U32 & String,RoutedConnection>

def RouteStep() -> Type:
  RoutedConnection & Result<&1,&1,U32 & String,SelectedRoute>

def route_step(conn: Connection(), state: RecoveryState, route: SelectedRoute) -> IO(RouteStep()):
  IO.pure(RouteStep(),(Routed{conn,state},Done{route}))

def route_error(conn: Connection(), state: RecoveryState, error: U32 & String) -> IO(RouteStep()):
  IO.pure(RouteStep(),(Routed{conn,state},Fail{error}))

def arm_recovery(conn: Connection()) -> IO(Connection() & Result<&1,&1,U32 & String,Unit>):
  use_connection(Result<&1,&1,U32 & String,Unit>,conn,c => Quic.monitor_quic_path(c,1000))

def start_watching(monitored: Connection() & Result<&1,&1,U32 & String,Unit>, plan: RecoveryPlan)
    -> IO(RoutedResult()):
  match monitored:
    case (conn,Done{_}):
      IO.pure(RoutedResult(),Done{Routed{conn,Watching{plan}}})
    case (conn,Fail{error}):
      do IO<RoutedResult()>:
        _ : Result<&1,&1,U32 & String,Unit> <- disconnect(conn)
        return Fail{error}

def relay_search(plan: RecoveryPlan, now: U32, direct: List<&2,Address>) -> RecoveryState:
  match direct:
    case Nil{}:
      OnRelay{}
    case Con{_,_}:
      SeekingDirect{plan,[],now}

def on_relay(+plan: RecoveryPlan) -> IO(RecoveryState):
  RelayFallback{_,_,direct,_} = plan
  do IO<RecoveryState>:
    now : U32 <- Quic.quic_millis()
    return relay_search(plan,now,direct)

def routed_dial(result: ConnectResult(), urls: List<&2,String>, +direct: List<&2,Address>,
    identity: Identity, timeouts: Timeouts) -> IO(RoutedResult()):
  match result urls:
    case Fail{error} _:
      IO.pure(RoutedResult(),Fail{error})
    case Done{(conn,Some{bridge})} relays:
      HandshakeTimeouts{_,probe_ms} = timeouts
      do IO<RoutedResult()>:
        next : RecoveryState <- on_relay(RelayFallback{identity,relays,direct,probe_ms})
        return Done{Routed{(conn,Some{bridge}),next}}
    case Done{(conn,None{})} Nil{}:
      IO.pure(RoutedResult(),Done{Routed{(conn,None{}),DirectOnly{}}})
    case Done{(conn,None{})} Con{url,rest}:
      HandshakeTimeouts{_,probe_ms} = timeouts
      do IO<RoutedResult()>:
        monitored : Connection() & Result<&1,&1,U32 & String,Unit> <- arm_recovery((conn,None{}))
        start_watching(monitored,RelayFallback{identity,Con{url,rest},direct,probe_ms})

# Dial using the normal route order and retain relays for later recovery.
def connect_routed(+routes: Routes, +identity: Identity, +timeouts: Timeouts) -> IO(RoutedResult()):
  DialRoutes{direct,urls} = routes
  do IO<RoutedResult()>:
    connected : ConnectResult() <- connect_routes(routes,identity,timeouts)
    routed_dial(connected,urls,direct,identity,timeouts)

def restarted_monitor(monitored: Connection() & Result<&1,&1,U32 & String,Unit>, plan: RecoveryPlan) -> IO(RouteStep()):
  match monitored:
    case (conn,Done{_}):
      route_step(conn,Watching{plan},DirectRoute{})
    case (conn,Fail{error}):
      route_error(conn,Watching{plan},error)

def skip_relay(conn: Connection(), plan: RecoveryPlan, remaining: List<&2,String>) -> IO(RouteStep()):
  (quic,bridge) = conn
  match bridge:
    case None{}:
      route_step((quic,None{}),DialingRelay{plan,remaining},DirectRoute{})
    case Some{path}:
      do IO<RouteStep()>:
        _ : Result<&1,&1,U32 & String,Unit> <- Path.stop(path)
        route_step((quic,None{}),DialingRelay{plan,remaining},DirectRoute{})

def opened_relay(conn: Quic.DatagramConnection, attachment: Result<&1,&1,U32 & String,Path.Bridge & U32>,
    plan: RecoveryPlan, rest: List<&2,String>) -> IO(RouteStep()):
  match attachment:
    case Done{(bridge,port)}:
      do IO<RouteStep()>:
        now : U32 <- Quic.quic_millis()
        route_step((conn,Some{bridge}),ProbingRelay{plan,rest,port,now},DirectRoute{})
    case Fail{_}:
      route_step((conn,None{}),DialingRelay{plan,rest},DirectRoute{})

def start_standby(conn: Connection(), +plan: RecoveryPlan, url: String, rest: List<&2,String>) -> IO(RouteStep()):
  (quic,_) = conn
  RelayFallback{PeerKeys{seed,peer,_},_,_,_} = plan
  do IO<RouteStep()>:
    bridge : Result<&1,&1,U32 & String,Path.Bridge & U32> <- Path.start(url,seed,peer,0)
    opened_relay(quic,bridge,plan,rest)

def dial_standby(conn: Connection(), plan: RecoveryPlan, remaining: List<&2,String>) -> IO(RouteStep()):
  match remaining:
    case Con{url,rest}:
      start_standby(conn,plan,url,rest)
    case Nil{}:
      do IO<RouteStep()>:
        monitored : Connection() & Result<&1,&1,U32 & String,Unit> <- arm_recovery(conn)
        restarted_monitor(monitored,plan)

def watch_path(conn: Connection(), +plan: RecoveryPlan, stalled: Bool) -> IO(RouteStep()):
  RelayFallback{_,urls,_,_} = plan
  match stalled:
    case True{}:
      dial_standby(conn,plan,urls)
    case False{}:
      route_step(conn,Watching{plan},DirectRoute{})

def watch_input(input: Connection() & Result<&1,&1,U32 & String,U32 & U32>, plan: RecoveryPlan) -> IO(RouteStep()):
  match input:
    case (conn,Done{(+idle,pto)}):
      watch_path(conn,plan,U32.is_ge(idle,3500) && U32.is_ge(U32.div(idle,3),pto))
    case (conn,Fail{error}):
      route_error(conn,Watching{plan},error)

def after_relay_probe(result: Connection() & Result<&1,&1,U32 & String,U32>, plan: RecoveryPlan,
    remaining: List<&2,String>, port: U32, since: U32, expired: Bool) -> IO(RouteStep()):
  match result expired:
    case (conn,Done{0}) False{}:
      route_step(conn,ProbingRelay{plan,remaining,port,since},DirectRoute{})
    case (conn,Done{0}) True{}:
      skip_relay(conn,plan,remaining)
    case (conn,Done{_}) _:
      route_step(conn,ValidatingRelay{plan,remaining},DirectRoute{})
    case (conn,Fail{_}) _:
      skip_relay(conn,plan,remaining)

def completed_relay(result: Connection() & Result<&1,&1,U32 & String,Unit>, plan: RecoveryPlan) -> IO(RouteStep()):
  match result:
    case (conn,Done{_}):
      do IO<RouteStep()>:
        next : RecoveryState <- on_relay(plan)
        route_step(conn,next,RelayRoute{})
    case (conn,Fail{error}):
      route_error(conn,OnRelay{},error)

def observe_relay(result: Connection() & Result<&1,&1,U32 & String,U32>, plan: RecoveryPlan,
    remaining: List<&2,String>) -> IO(RouteStep()):
  match result:
    case (conn,Done{2}):
      do IO<RouteStep()>:
        unmonitored : Connection() & Result<&1,&1,U32 & String,Unit> <-
          use_connection(Result<&1,&1,U32 & String,Unit>,conn,c => Quic.monitor_quic_path(c,0))
        completed_relay(unmonitored,plan)
    case (conn,Done{1}):
      route_step(conn,ValidatingRelay{plan,remaining},DirectRoute{})
    case (conn,Done{_}):
      skip_relay(conn,plan,remaining)
    case (conn,Fail{error}):
      route_error(conn,ValidatingRelay{plan,remaining},error)

def next_direct(conn: Connection(), plan: RecoveryPlan, remaining: List<&2,Address>) -> IO(RouteStep()):
  do IO<RouteStep()>:
    now : U32 <- Quic.quic_millis()
    route_step(conn,SeekingDirect{plan,remaining,now},RelayRoute{})

def after_direct_probe(result: Connection() & Result<&1,&1,U32 & String,U32>, plan: RecoveryPlan,
    peer: Address, rest: List<&2,Address>, since: U32, expired: Bool) -> IO(RouteStep()):
  match result expired:
    case (conn,Done{0}) False{}:
      route_step(conn,SeekingDirect{plan,Con{peer,rest},since},RelayRoute{})
    case (conn,Done{0}) True{}:
      next_direct(conn,plan,rest)
    case (conn,Done{_}) _:
      route_step(conn,ValidatingDirect{plan,rest},RelayRoute{})
    case (conn,Fail{_}) _:
      next_direct(conn,plan,rest)

def retry_direct(conn: Connection(), +plan: RecoveryPlan, since: U32, now: U32, due: Bool) -> IO(RouteStep()):
  RelayFallback{_,_,direct,_} = plan
  match due:
    case True{}:
      route_step(conn,SeekingDirect{plan,direct,now},RelayRoute{})
    case False{}:
      route_step(conn,SeekingDirect{plan,[],since},RelayRoute{})

def seek_direct(conn: Connection(), +plan: RecoveryPlan, remaining: List<&2,Address>, +since: U32) -> IO(RouteStep()):
  RelayFallback{_,_,_,timeout} = plan
  match remaining:
    case Nil{}:
      do IO<RouteStep()>:
        +now : U32 <- Quic.quic_millis()
        retry_direct(conn,plan,since,now,U32.is_ge(U32.sub(now,since),1000))
    case Con{+peer,rest}:
      do IO<RouteStep()>:
        now : U32 <- Quic.quic_millis()
        result : Connection() & Result<&1,&1,U32 & String,U32> <- start_path_migration(conn,IpAddress{"",0},peer)
        after_direct_probe(result,plan,peer,rest,since,U32.is_ge(U32.sub(now,since),timeout))

def release_old_relay(conn: Connection()) -> IO(Connection()):
  (quic,bridge) = conn
  match bridge:
    case None{}:
      IO.pure(Connection(),(quic,None{}))
    case Some{path}:
      do IO<Connection()>:
        _ : Result<&1,&1,U32 & String,Unit> <- Path.stop(path)
        return (quic,None{})

def observe_direct(result: Connection() & Result<&1,&1,U32 & String,U32>, plan: RecoveryPlan,
    rest: List<&2,Address>) -> IO(RouteStep()):
  match result:
    case (conn,Done{2}):
      do IO<RouteStep()>:
        direct : Connection() <- release_old_relay(conn)
        monitored : Connection() & Result<&1,&1,U32 & String,Unit> <- arm_recovery(direct)
        restarted_monitor(monitored,plan)
    case (conn,Done{1}):
      route_step(conn,ValidatingDirect{plan,rest},RelayRoute{})
    case (conn,Done{_}):
      next_direct(conn,plan,rest)
    case (conn,Fail{error}):
      route_error(conn,ValidatingDirect{plan,rest},error)

def advance_recovery(conn: Connection(), state: RecoveryState) -> IO(RouteStep()):
  match state:
    case DirectOnly{}:
      route_step(conn,DirectOnly{},DirectRoute{})
    case OnRelay{}:
      route_step(conn,OnRelay{},RelayRoute{})
    case Watching{plan}:
      do IO<RouteStep()>:
        timing : Connection() & Result<&1,&1,U32 & String,U32 & U32> <-
          use_connection(Result<&1,&1,U32 & String,U32 & U32>,conn,Quic.quic_path_timing)
        watch_input(timing,plan)
    case DialingRelay{plan,rest}:
      dial_standby(conn,plan,rest)
    case ProbingRelay{+plan,rest,+port,+since}:
      RelayFallback{_,_,_,timeout} = plan
      do IO<RouteStep()>:
        now : U32 <- Quic.quic_millis()
        candidate : Connection() & Result<&1,&1,U32 & String,U32> <-
          start_path_migration(conn,IpAddress{"127.0.0.1",0},IpAddress{"127.0.0.1",port})
        after_relay_probe(candidate,plan,rest,port,since,U32.is_ge(U32.sub(now,since),timeout))
    case ValidatingRelay{plan,rest}:
      do IO<RouteStep()>:
        validation : Connection() & Result<&1,&1,U32 & String,U32> <-
          use_connection(Result<&1,&1,U32 & String,U32>,conn,Quic.quic_migration_status)
        observe_relay(validation,plan,rest)
    case SeekingDirect{plan,rest,since}:
      seek_direct(conn,plan,rest,since)
    case ValidatingDirect{plan,rest}:
      do IO<RouteStep()>:
        validation : Connection() & Result<&1,&1,U32 & String,U32> <-
          use_connection(Result<&1,&1,U32 & String,U32>,conn,Quic.quic_migration_status)
        observe_direct(validation,plan,rest)

def recovery_progress(result: Connection() & Result<&1,&1,U32 & String,U32>, state: RecoveryState) -> IO(RouteStep()):
  match result:
    case (conn,Done{_}):
      advance_recovery(conn,state)
    case (conn,Fail{error}):
      route_error(conn,state,error)

# Drive QUIC and migrate the same connection between direct and relay routes.
def step_routes(owner: RoutedConnection) -> IO(RouteStep()):
  Routed{conn,state} = owner
  do IO<RouteStep()>:
    progress : Connection() & Result<&1,&1,U32 & String,U32> <-
      use_connection(Result<&1,&1,U32 & String,U32>,conn,Quic.step_quic_datagram)
    recovery_progress(progress,state)

def keep_routes(-R: Type, pair: Connection() & R, state: RecoveryState) -> RoutedConnection & R:
  (conn,value) = pair
  (Routed{conn,state},value)

def use_routed_connection(-R: Type, owner: RoutedConnection,
    operation: Quic.DatagramConnection -> IO(Quic.DatagramConnection & R)) -> IO(RoutedConnection & R):
  Routed{conn,state} = owner
  do IO<RoutedConnection & R>:
    result : Connection() & R <- use_connection(R,conn,operation)
    return keep_routes(R,result,state)

def close_routes(owner: RoutedConnection) -> IO(Result<&1,&1,U32 & String,Unit>):
  Routed{conn,_} = owner
  disconnect(conn)

def bind_with_idle_timeout(address: Address, identity: Identity, idle_ms: NatWire.VarInt)
    -> IO(Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32>):
  IpAddress{host,port} = address
  PeerKeys{seed,peer,alpn} = identity
  Quic.bind_shared_quic_with_idle_timeout(host,port,seed,peer,alpn,idle_ms)

def bind(address: Address, identity: Identity) -> IO(Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32>):
  bind_with_idle_timeout(address,identity,Close.default_idle_timeout())

def bind_identity_with_idle_timeout(address: Address, seed: List<&2,U32>, alpn: List<&2,U32>, early_data: U32,
    idle_ms: NatWire.VarInt)
    -> IO(Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32>):
  IpAddress{host,port} = address
  Quic.bind_quic_identity_with_idle_timeout(host,port,seed,alpn,early_data,idle_ms)

def bind_identity(address: Address, seed: List<&2,U32>, alpn: List<&2,U32>, early_data: U32)
    -> IO(Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32>):
  bind_identity_with_idle_timeout(address,seed,alpn,early_data,Close.default_idle_timeout())

def remote_id(owner: Connection()) -> IO(Connection() & Result<&1,&1,U32 & String,List<&2,U32>>):
  use_connection(Result<&1,&1,U32 & String,List<&2,U32>>,owner,Quic.quic_remote_id)

def accepted(listener: Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.DatagramConnection>>)
    -> Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Connection()>>:
  match listener:
    case (owner,Done{Some{conn}}):
      (owner,Done{Some{(conn,None{})}})
    case (owner,Done{None{}}):
      (owner,Done{None{}})
    case (owner,Fail{error}):
      (owner,Fail{error})

def try_accept(listener: Quic.QuicDatagramListener)
    -> IO(Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Connection()>>):
  do IO<Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Connection()>>>:
    outcome : Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.DatagramConnection>> <-
      Quic.try_accept_shared_quic(listener)
    return accepted(outcome)

type RelayedListener is Type:
  RelayListener{listener: Quic.QuicDatagramListener, bridge: Path.Bridge}

def attached_listener(result: Result<&1,&1,U32 & String,Path.Bridge>, listener: Quic.QuicDatagramListener, port: U32)
    -> IO(Result<&1,&1,U32 & String,RelayedListener & U32>):
  match result:
    case Done{bridge}:
      IO.pure(Result<&1,&1,U32 & String,RelayedListener & U32>,Done{(RelayListener{listener,bridge},port)})
    case Fail{error}:
      do IO<Result<&1,&1,U32 & String,RelayedListener & U32>>:
        Quic.close_shared_quic(listener)
        return Fail{error}

def attach_inbound(result: Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32>,
    url: String, seed: List<&2,U32>,
    start: String -> List<&2,U32> -> U32 -> IO(Result<&1,&1,U32 & String,Path.Bridge>))
    -> IO(Result<&1,&1,U32 & String,RelayedListener & U32>):
  match result:
    case Done{(listener,+port)}:
      do IO<Result<&1,&1,U32 & String,RelayedListener & U32>>:
        bridge : Result<&1,&1,U32 & String,Path.Bridge> <- start(url,seed,port)
        attached_listener(bridge,listener,port)
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,RelayedListener & U32>,Fail{error})

def relay_only(bound: Result<&1,&1,U32 & String,RelayedListener & U32>) -> Result<&1,&1,U32 & String,RelayedListener>:
  match bound:
    case Done{(listener,_)}:
      Done{listener}
    case Fail{error}:
      Fail{error}

# Keep the listener alive while its accepted relay connections are in use.
def bind_relay_identity_with_idle_timeout(url: String, +seed: List<&2,U32>, alpn: List<&2,U32>, early_data: U32,
    idle_ms: NatWire.VarInt)
    -> IO(Result<&1,&1,U32 & String,RelayedListener>):
  do IO<Result<&1,&1,U32 & String,RelayedListener>>:
    bound : Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32> <-
      bind_identity_with_idle_timeout(IpAddress{"127.0.0.1",0},seed,alpn,early_data,idle_ms)
    attached : Result<&1,&1,U32 & String,RelayedListener & U32> <- attach_inbound(bound,url,seed,
      address => secret => port => Inbound.start(address,secret,port))
    return relay_only(attached)

def bind_relay_identity(url: String, seed: List<&2,U32>, alpn: List<&2,U32>, early_data: U32)
    -> IO(Result<&1,&1,U32 & String,RelayedListener>):
  bind_relay_identity_with_idle_timeout(url,seed,alpn,early_data,Close.default_idle_timeout())

# Share one identity, accept queue, and connection table between IPv4 and IPv6
# direct traffic and the relay. Registration proceeds in the background.
# Pass port zero to select a UDP port.
def bind_direct_relay_identity_with_idle_timeout(port: U32, url: String, +seed: List<&2,U32>, alpn: List<&2,U32>, early_data: U32,
    idle_ms: NatWire.VarInt)
    -> IO(Result<&1,&1,U32 & String,RelayedListener & U32>):
  do IO<Result<&1,&1,U32 & String,RelayedListener & U32>>:
    bound : Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32> <-
      Quic.bind_dual_quic_identity_with_idle_timeout("::",port,seed,alpn,early_data,idle_ms)
    attach_inbound(bound,url,seed,address => secret => local => Inbound.start_background(address,secret,local))

def bind_direct_relay_identity(port: U32, url: String, seed: List<&2,U32>, alpn: List<&2,U32>, early_data: U32)
    -> IO(Result<&1,&1,U32 & String,RelayedListener & U32>):
  bind_direct_relay_identity_with_idle_timeout(port,url,seed,alpn,early_data,Close.default_idle_timeout())

def accepted_relay(pair: Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Connection()>>,
    bridge: Path.Bridge) -> RelayedListener & Result<&1,&1,U32 & String,Maybe<&1,Connection()>>:
  (listener,result) = pair
  (RelayListener{listener,bridge},result)

def try_accept_relay_identity(owner: RelayedListener)
    -> IO(RelayedListener & Result<&1,&1,U32 & String,Maybe<&1,Connection()>>):
  RelayListener{listener,bridge} = owner
  do IO<RelayedListener & Result<&1,&1,U32 & String,Maybe<&1,Connection()>>>:
    outcome : Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Connection()>> <- try_accept(listener)
    return accepted_relay(outcome,bridge)

def close_relay_identity(owner: RelayedListener) -> IO(Result<&1,&1,U32 & String,Unit>):
  RelayListener{listener,bridge} = owner
  do IO<Result<&1,&1,U32 & String,Unit>>:
    Quic.close_shared_quic(listener)
    Path.stop(bridge)

def close_listener(listener: Quic.QuicDatagramListener) -> IO(Unit):
  Quic.close_shared_quic(listener)

# Opt in to receiving replayable 0-RTT data on this listener.
def bind_resumable_with_idle_timeout(address: Address, identity: Identity, idle_ms: NatWire.VarInt)
    -> IO(Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32>):
  IpAddress{host,port} = address
  PeerKeys{seed,peer,alpn} = identity
  Quic.bind_resumable_quic_with_idle_timeout(host,port,seed,peer,alpn,idle_ms)

def bind_resumable(address: Address, identity: Identity)
    -> IO(Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32>):
  bind_resumable_with_idle_timeout(address,identity,Close.default_idle_timeout())
