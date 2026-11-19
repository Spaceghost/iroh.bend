import Base
import ./direct.bend as Direct
import ./discovery.bend as Dns
import ./pkarr.bend as Pkarr
import ./relay_quic.bend as Path

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

def Connected() -> Type:
  Direct.QuicConnection & Maybe<&1,Path.Bridge>

def Outcome() -> Type:
  Result<&1,&1,U32 & String,Connected()>

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

def try_relay(url: String, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  PeerKeys{+seed,+peer,alpn} = identity
  HandshakeTimeouts{_,relay_ms} = timeouts
  do IO<Outcome()>:
    bridge : Result<&1,&1,U32 & String,Path.Bridge & U32> <- Path.start(url,seed,peer,0)
    Path.dial_attached(bridge,seed,peer,alpn,relay_ms)

def try_direct(address: Address, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  IpAddress{host,port} = address
  PeerKeys{seed,peer,alpn} = identity
  HandshakeTimeouts{direct_ms,_} = timeouts
  do IO<Outcome()>:
    conn : Result<&1,&1,U32 & String,Direct.QuicConnection> <-
      Direct.quic_connect_with_timeout(host,port,seed,peer,alpn,direct_ms)
    return Result.map(&1,&1,U32 & String,Direct.QuicConnection,Connected(),c => (c,None{}),conn)

def continue_dial(outcome: Outcome(), next: (U32 & String) -> IO(Outcome())) -> IO(Outcome()):
  match outcome:
    case Done{conn}:
      IO.pure(Outcome(),Done{conn})
    case Fail{error}:
      next(error)

def try_relays(urls: List<&2,String>, +identity: Identity, +timeouts: Timeouts, last: U32 & String) -> IO(Outcome()):
  match urls:
    case Nil{}:
      IO.pure(Outcome(),Fail{last})
    case Con{url,rest}:
      do IO<Outcome()>:
        outcome : Outcome() <- try_relay(url,identity,timeouts)
        continue_dial(outcome,error => try_relays(rest,identity,timeouts,error))

def try_ips(ips: List<&2,Address>, urls: List<&2,String>, +identity: Identity, +timeouts: Timeouts,
    last: U32 & String) -> IO(Outcome()):
  match ips:
    case Nil{}:
      try_relays(urls,identity,timeouts,last)
    case Con{ip,rest}:
      do IO<Outcome()>:
        outcome : Outcome() <- try_direct(ip,identity,timeouts)
        continue_dial(outcome,error => try_ips(rest,urls,identity,timeouts,error))

def dial_routes(plan: Routes, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  DialRoutes{ips,urls} = plan
  try_ips(ips,urls,identity,timeouts,(1,"endpoint has no usable direct address or relay"))

# Try published direct addresses, followed by published relays. QUIC pins
# the peer to the endpoint key on either kind of path.
def dial(records: List<&2,Dns.Attribute>, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  dial_routes(routes(records),identity,timeouts)

def from_dns(reply: Result<&1,&1,U32 & String,Dns.Reply>, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  match reply:
    case Done{Dns.Found{records}}:
      dial(records,identity,timeouts)
    case Done{Dns.DnsError{code}}:
      IO.pure(Outcome(),Fail{(code,"endpoint DNS lookup returned an error")})
    case Done{_}:
      IO.pure(Outcome(),Fail{(1,"endpoint DNS lookup did not return usable records")})
    case Fail{error}:
      IO.pure(Outcome(),Fail{error})

def lookup_and_dial(+identity: Identity, resolver: DnsSource, timeouts: Timeouts) -> IO(Outcome()):
  PeerKeys{_,key,_} = identity
  DnsResolver{origin,host,port,ms} = resolver
  do IO<Outcome()>:
    reply : Result<&1,&1,U32 & String,Dns.Reply> <- Dns.lookup(key,origin,host,port,ms)
    from_dns(reply,identity,timeouts)

def from_pkarr(verified: Pkarr.Verification, identity: Identity, timeouts: Timeouts) -> IO(Outcome()):
  match verified:
    case Pkarr.Verified{_,records}:
      dial(records,identity,timeouts)
    case _:
      IO.pure(Outcome(),Fail{(1,"invalid signed Pkarr endpoint packet")})

def verify_and_dial(+identity: Identity, packet: List<&2,U32>, timeouts: Timeouts) -> IO(Outcome()):
  PeerKeys{_,key,_} = identity
  do IO<Outcome()>:
    verified : Pkarr.Verification <- Pkarr.verify(key,packet)
    from_pkarr(verified,identity,timeouts)
