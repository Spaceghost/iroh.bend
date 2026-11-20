import Base
import ../src/ed25519.bend as Ed
import ../src/endpoint.bend as Endpoint

def alpn(choice: String) -> List<&2,U32>:
  match choice:
    case "self":
      [0,255]
    case _:
      []

def remote_seed(choice: String) -> U32:
  match choice:
    case "empty":
      42
    case _:
      73

def identity(+choice: String) -> IO(Endpoint.Identity):
  do IO<Endpoint.Identity>:
    peer : List<&2,U32> <- IO.try(List<&2,U32>,Ed.public_key(List.replicate(U32,32n,remote_seed(choice))))
    return Endpoint.PeerKeys{List.replicate(U32,32n,73),peer,alpn(choice)}

def ip(port: U32) -> Endpoint.Address:
  Endpoint.IpAddress{"127.0.0.1",port}

def url(port: U32) -> String:
  "ws://127.0.0.1:" ++ U32.show(port) ++ "/relay"

def routes(+port: U32) -> Endpoint.Routes:
  Endpoint.DialRoutes{[ip(port)],[url(port)]}

def dns(port: U32) -> Endpoint.DnsSource:
  Endpoint.DnsResolver{"dns.iroh.link.","127.0.0.1",port,100}

def timeouts() -> Endpoint.Timeouts:
  Endpoint.HandshakeTimeouts{100,100}

def rejection(-C: Type, outcome: Result<&1,&1,U32 & String,C>) -> IO(Unit):
  match outcome:
    case Fail{(22,message)}:
      IO.print(message)
    case Fail{(code,message)}:
      IO.die(Unit,code,message)
    case Done{_}:
      IO.die(Unit,1,"unexpected connection")
