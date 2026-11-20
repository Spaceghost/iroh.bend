import Base
import ../src/endpoint.bend as Endpoint
import ../src/quic_nat.bend as Wire

type Candidate is Data:
  Supplied{routes: Endpoint.Routes}
  Discovered{source: Endpoint.AddressLookup}

type Request is Data:
  Route{candidate: Candidate, setting: String}

def candidate(dns: Bool, host: String, port: U32, command: String, setting: String) -> Maybe<&2,Request>:
  match dns:
    case True{}:
      Some{Route{Discovered{Endpoint.DnsLookup{Endpoint.DnsResolver{"dns.iroh.link.",host,port,5000}}},setting}}
    case False{}:
      Bool.pick(Maybe<&2,Request>,String.eq(command,"route-idle"),
        Some{Route{Supplied{Endpoint.DialRoutes{[Endpoint.IpAddress{host,port}],[]}},setting}},None{})

def direct_or_dns(host: String, port: Maybe<&2,U32>, +command: String, setting: String) -> Maybe<&2,Request>:
  match port:
    case None{}:
      None{}
    case Some{p}:
      candidate(String.eq(command,"dns-idle"),host,p,command,setting)

def parse(args: List<String>) -> Maybe<&2,Request>:
  match args:
    case [_,host,port,command,setting]:
      direct_or_dns(host,U32.read(port),command,setting)
    case [_,url,command,setting]:
      Bool.pick(Maybe<&2,Request>,String.eq(command,"relay-idle"),
        Some{Route{Supplied{Endpoint.DialRoutes{[],[url]}},setting}},None{})
    case _:
      None{}

def connect(~C: Type,
    ~supplied: Endpoint.Routes -> Endpoint.Identity -> Endpoint.Timeouts -> Wire.VarInt -> IO(Endpoint.TransportResult(C)),
    ~lookup: Endpoint.Routes -> Endpoint.Identity -> Endpoint.Timeouts -> List<&2,Endpoint.AddressLookup> -> Wire.VarInt -> IO(Endpoint.TransportResult(C)),
    candidate: Candidate, identity: Endpoint.Identity, timeouts: Endpoint.Timeouts, idle_ms: Wire.VarInt) -> IO(Endpoint.TransportResult(C)):
  match candidate:
    case Supplied{routes}:
      supplied(routes,identity,timeouts,idle_ms)
    case Discovered{source}:
      lookup(Endpoint.DialRoutes{[],[]},identity,timeouts,[source],idle_ms)
