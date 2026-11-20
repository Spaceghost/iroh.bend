import Base
import ./endpoint_ticket.bend as Tickets
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

def relay_url(+bytes: List<&2,U32>) -> Maybe<&2,String>:
  decoded_relay(bytes,ascii(bytes))

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

# Try each published direct address before opening a relay path. The returned
# QUIC connection exposes both streams and application datagrams.
def connect_routes(plan: Routes, identity: Identity, timeouts: Timeouts) -> IO(ConnectResult()):
  dial_plan(~Quic.DatagramConnection,~direct_quic,plan,identity,timeouts)

def connect_ticket(text: String, seed: List<&2,U32>, alpn: List<&2,U32>, timeouts: Timeouts) -> IO(ConnectResult()):
  with_ticket(~Connection(),~connect_routes,text,seed,alpn,timeouts)

def connect(records: List<&2,Dns.Attribute>, identity: Identity, timeouts: Timeouts) -> IO(ConnectResult()):
  connect_routes(routes(records),identity,timeouts)

def dns_routes(reply: Result<&1,&1,U32 & String,Dns.Reply>) -> Result<&1,&1,U32 & String,Routes>:
  match reply:
    case Done{Dns.Found{records}}:
      Done{routes(records)}
    case Done{Dns.DnsError{code}}:
      Fail{(code,"endpoint DNS lookup returned an error")}
    case Done{_}:
      Fail{(1,"endpoint DNS lookup did not return usable records")}
    case Fail{error}:
      Fail{error}

def lookup_routes(identity: Identity, resolver: DnsSource) -> IO(Result<&1,&1,U32 & String,Routes>):
  PeerKeys{_,key,_} = identity
  DnsResolver{origin,host,port,ms} = resolver
  do IO<Result<&1,&1,U32 & String,Routes>>:
    reply : Result<&1,&1,U32 & String,Dns.Reply> <- Dns.lookup(key,origin,host,port,ms)
    return dns_routes(reply)

def pkarr_routes(verified: Pkarr.Verification) -> Result<&1,&1,U32 & String,Routes>:
  match verified:
    case Pkarr.Verified{_,records}:
      Done{routes(records)}
    case _:
      Fail{(1,"invalid signed Pkarr endpoint packet")}

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

def LookupReply() -> Type:
  Result<&1,&1,U32 & String,Routes>

def resolve_until(source: AddressLookup, +key: List<&2,U32>, +stop: Chan(Unit)) -> IO(LookupReply()):
  match source:
    case DnsLookup{DnsResolver{origin,host,port,ms}}:
      do IO<LookupReply()>:
        id : Result<&1,&1,U32 & String,U32> <- IO.random_u32()
        reply : Result<&1,&1,U32 & String,Dns.Reply> <- Dns.lookup_using(id,key,origin,host,port,ms,
          Dns.StopOnClose{stop},name => p => timeout => LookupSocket.connect(stop,name,p,timeout))
        return dns_routes(reply)
    case PkarrLookup{url,ms}:
      do IO<LookupReply()>:
        proof : PkarrHttp.Proof() <- PkarrHttp.resolve_until(url,key,ms,stop)
        return pkarr_reply(proof)

def publish_lookup(source: AddressLookup, key: List<&2,U32>, results: Chan(LookupReply()), stop: Chan(Unit)) -> IO(Unit):
  do IO<Unit>:
    reply : LookupReply() <- resolve_until(source,key,stop)
    _ : Result<&1,&1,LookupReply(),Unit> <- Chan.send(LookupReply(),results,reply)
    return Unit{}

def start_lookups(sources: List<&2,AddressLookup>, +key: List<&2,U32>, +results: Chan(LookupReply()),
    +stop: Chan(Unit)) -> IO(Unit):
  match sources:
    case Nil{}:
      IO.pure(Unit,Unit{})
    case Con{source,rest}:
      do IO<Unit>:
        IO.spawn(Unit,publish_lookup(source,key,results,stop))
        start_lookups(rest,key,results,stop)

def drain_lookups(remaining: Nat, +results: Chan(LookupReply())) -> IO(Unit):
  match remaining:
    case 0n:
      Chan.close(LookupReply(),results)
    case 1n+k:
      do IO<Unit>:
        _ : Maybe<&1,LookupReply()> <- Chan.recv(LookupReply(),results)
        drain_lookups(k,results)

def accept_lookup(event: Maybe<&1,LookupReply()>, identity: Identity, timeouts: Timeouts) -> IO(ConnectResult()):
  match event:
    case Some{reply}:
      dial_resolved(~Quic.DatagramConnection,~direct_quic,reply,identity,timeouts)
    case None{}:
      IO.pure(ConnectResult(),Fail{(1,"address lookup ended early")})

def collect_lookups(+remaining: Nat, outcome: ConnectResult(), +results: Chan(LookupReply()),
    +identity: Identity, +timeouts: Timeouts, +stop: Chan(Unit)) -> IO(ConnectResult()):
  match remaining outcome:
    case 1n+k Fail{_}:
      do IO<ConnectResult()>:
        event : Maybe<&1,LookupReply()> <- Chan.recv(LookupReply(),results)
        next : ConnectResult() <- accept_lookup(event,identity,timeouts)
        collect_lookups(k,next,results,identity,timeouts,stop)
    case _ _:
      do IO<ConnectResult()>:
        Chan.close(Unit,stop)
        drain_lookups(remaining,results)
        return outcome

def try_lookups(+sources: List<&2,AddressLookup>, outcome: ConnectResult(), +identity: Identity,
    timeouts: Timeouts) -> IO(ConnectResult()):
  match sources outcome:
    case Con{_,_} Fail{_}:
      PeerKeys{_,key,_} = identity
      +count = List.length(&2,AddressLookup,sources)
      do IO<ConnectResult()>:
        +results : Chan(LookupReply()) <- Chan.new(LookupReply(),U32.from_nat(count))
        +stop : Chan(Unit) <- Chan.new(Unit,0)
        start_lookups(sources,key,results,stop)
        collect_lookups(count,outcome,results,identity,timeouts,stop)
    case _ _:
      IO.pure(ConnectResult(),outcome)

def connect_with_lookup(plan: Routes, +identity: Identity, +timeouts: Timeouts, sources: List<&2,AddressLookup>)
    -> IO(ConnectResult()):
  before_connect(Connection(),identity,u =>
    do IO<ConnectResult()>:
      tried : ConnectResult() <- dial_validated_plan(~Quic.DatagramConnection,~direct_quic,~direct_quic,plan,identity,timeouts)
      try_lookups(sources,tried,identity,timeouts))

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
  resolve_and_connect(~Quic.DatagramConnection,~direct_quic,identity,timeouts,key => lookup_routes(key,resolver))

def verify_and_connect(+identity: Identity, packet: List<&2,U32>, timeouts: Timeouts) -> IO(ConnectResult()):
  resolve_and_connect(~Quic.DatagramConnection,~direct_quic,identity,timeouts,key => verify_routes(key,packet))

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

def bind(address: Address, identity: Identity) -> IO(Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32>):
  IpAddress{host,port} = address
  PeerKeys{seed,peer,alpn} = identity
  Quic.bind_shared_quic(host,port,seed,peer,alpn)

def bind_identity(address: Address, seed: List<&2,U32>, alpn: List<&2,U32>, early_data: U32)
    -> IO(Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32>):
  IpAddress{host,port} = address
  Quic.bind_quic_identity(host,port,seed,alpn,early_data)

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
def bind_relay_identity(url: String, +seed: List<&2,U32>, alpn: List<&2,U32>, early_data: U32)
    -> IO(Result<&1,&1,U32 & String,RelayedListener>):
  do IO<Result<&1,&1,U32 & String,RelayedListener>>:
    bound : Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32> <-
      bind_identity(IpAddress{"127.0.0.1",0},seed,alpn,early_data)
    attached : Result<&1,&1,U32 & String,RelayedListener & U32> <- attach_inbound(bound,url,seed,
      address => secret => port => Inbound.start(address,secret,port))
    return relay_only(attached)

# Share one identity, accept queue, and connection table between IPv4 and IPv6
# direct traffic and the relay. Registration proceeds in the background.
# Pass port zero to select a UDP port.
def bind_direct_relay_identity(port: U32, url: String, +seed: List<&2,U32>, alpn: List<&2,U32>, early_data: U32)
    -> IO(Result<&1,&1,U32 & String,RelayedListener & U32>):
  do IO<Result<&1,&1,U32 & String,RelayedListener & U32>>:
    bound : Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32> <-
      Quic.bind_dual_quic_identity("::",port,seed,alpn,early_data)
    attach_inbound(bound,url,seed,address => secret => local => Inbound.start_background(address,secret,local))

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
def bind_resumable(address: Address, identity: Identity)
    -> IO(Result<&1,&1,U32 & String,Quic.QuicDatagramListener & U32>):
  IpAddress{host,port} = address
  PeerKeys{seed,peer,alpn} = identity
  Quic.bind_resumable_quic(host,port,seed,peer,alpn)
