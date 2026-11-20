import Base
import ../src/endpoint.bend as Endpoint
import ../src/endpoint_multipath.bend as Multipath
import ./quic_multipath_bend.bend as Fixture

def alpn() -> List<&2,U32>:
  [105,114,111,104,45,98,101,110,100,47,99,111,109,112,97,116,47,49]

def check_route(owner: Multipath.Connection(), relay: Bool, host: String, port: U32) -> IO(Unit):
  match owner relay:
    case (conn,None{}) False{}:
      Fixture.run_probe(conn,host,port)
    case (conn,Some{bridge}) True{}:
      do IO<Unit>:
        Fixture.run_probe(conn,host,port)
        IO.try(Unit,Multipath.stop_bridge(Some{bridge}))
    case route _:
      do IO<Unit>:
        _ : Result<&1,&1,U32 & String,Unit> <- Multipath.disconnect(route)
        IO.die(Unit,1,"endpoint chose the wrong initial route")

def lookup_source(text: String, port: Maybe<&2,U32>) -> Endpoint.AddressLookup:
  match port:
    case Some{p}:
      Endpoint.DnsLookup{Endpoint.DnsResolver{"dns.iroh.link.","127.0.0.1",p,12000}}
    case None{}:
      Endpoint.PkarrLookup{text,12000}

def ticket_lookup(text: String, sources: List<&2,Endpoint.AddressLookup>) -> IO(Multipath.ConnectResult()):
  match sources:
    case Nil{}:
      Multipath.connect_ticket(text,List.replicate(U32,32n,73),alpn(),Endpoint.HandshakeTimeouts{12000,12000})
    case Con{source,rest}:
      Multipath.connect_ticket_with_lookup(text,List.replicate(U32,32n,73),alpn(),Endpoint.HandshakeTimeouts{12000,12000},Con{source,rest})

def ticket_exchange(text: String, host: String, port: Maybe<&2,U32>, sources: List<&2,Endpoint.AddressLookup>, relay: Bool) -> IO(Unit):
  match port:
    case Some{n}:
      do IO<Unit>:
        owner : Multipath.Connection() <- IO.try(Multipath.Connection(),ticket_lookup(text,sources))
        check_route(owner,relay,host,n)
    case None{}:
      IO.die(Unit,2,"expected the Iroh direct port")

def ticket_args(args: List<String>, lookup: Bool) -> IO(Unit):
  match args lookup:
    case [text,_,host,port] False{}:
      ticket_exchange(text,host,U32.read(port),[],False{})
    case [text,route,host,port,+source] True{}:
      ticket_exchange(text,host,U32.read(port),[lookup_source(source,U32.read(source))],String.eq(route,"relay"))
    case _ _:
      IO.die(Unit,2,"expected a ticket, route, peer address and optional lookup source")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{command,tail}}:
      ticket_args(tail,String.eq(command,"lookup-ticket"))
    case _:
      IO.die(Unit,2,"expected a ticket command")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
