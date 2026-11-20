import Base
import ../src/discovery.bend as Dns
import ../src/endpoint.bend as Endpoint
import ../src/endpoint_ticket.bend as Tickets

def service(source: Endpoint.AddressLookup) -> String:
  match source:
    case Endpoint.DnsLookup{_}:
      "dns"
    case Endpoint.PkarrLookup{_,_}:
      "pkarr"

def error_text(error: Endpoint.LookupError) -> String:
  Endpoint.LookupError{source,code,message} = error
  service(source) ++ (" " ++ (U32.show(code) ++ (" " ++ message)))

def errors(items: List<&2,Endpoint.LookupError>) -> IO(Unit):
  match items:
    case Nil{}:
      IO.pure(Unit,Unit{})
    case Con{item,rest}:
      do IO<Unit>:
        IO.print("buffered " ++ error_text(item))
        errors(rest)

def assert_done(step: Endpoint.LookupStream & Endpoint.LookupEvent) -> IO(Unit):
  match step:
    case (stream,Endpoint.LookupEnd{}):
      do IO<Unit>:
        Endpoint.close_lookup(stream)
        IO.print("end")
    case (stream,_):
      do IO<Unit>:
        Endpoint.close_lookup(stream)
        IO.die(Unit,1,"address lookup emitted another terminal event")

def ended(stream: Endpoint.LookupStream) -> IO(Unit):
  do IO<Unit>:
    another : Endpoint.LookupStream & Endpoint.LookupEvent <- Endpoint.next_lookup(stream)
    assert_done(another)

def item_line(source: Endpoint.AddressLookup, valid: Bool) -> IO(Unit):
  match valid:
    case True{}:
      IO.print("item " ++ service(source))
    case False{}:
      IO.die(Unit,1,"address lookup item lost its endpoint ID or records")

def next_event(step: Endpoint.LookupStream & Endpoint.LookupEvent, key: List<&2,U32>,
    again: Endpoint.LookupStream -> IO(Unit)) -> IO(Unit):
  match step:
    case (stream,Endpoint.ServiceResult{Endpoint.FoundItem{Endpoint.LookupItem{id,source,records}}}):
      do IO<Unit>:
        item_line(source,Dns.bytes_eq(key,id) && Nat.is_gt(List.length(&2,Dns.Attribute,records),0n))
        again(stream)
    case (stream,Endpoint.ServiceResult{Endpoint.SourceError{error}}):
      do IO<Unit>:
        IO.print("error " ++ error_text(error))
        again(stream)
    case (stream,Endpoint.NoServiceConfigured{}):
      do IO<Unit>:
        IO.print("no service")
        ended(stream)
    case (stream,Endpoint.NoResults{failures}):
      do IO<Unit>:
        IO.print("no results")
        errors(failures)
        ended(stream)
    case (stream,Endpoint.LookupEnd{}):
      do IO<Unit>:
        IO.print("finished")
        ended(stream)

@unsafe def read_stream(stream: Endpoint.LookupStream, +key: List<&2,U32>) -> IO(Unit):
  do IO<Unit>:
    step : Endpoint.LookupStream & Endpoint.LookupEvent <- Endpoint.next_lookup(stream)
    next_event(step,key,next => read_stream(next,key))

def lookup(ticket: Maybe<&2,Tickets.EndpointTicket>, sources: Maybe<&2,List<&2,Endpoint.AddressLookup>>) -> IO(Unit):
  match ticket sources:
    case Some{Tickets.Ticket{+key,_}} Some{configured}:
      do IO<Unit>:
        stream : Endpoint.LookupStream <- Endpoint.resolve_addresses(configured,key)
        read_stream(stream,key)
    case _ _:
      IO.die(Unit,2,"invalid address lookup test input")

def run(text: String, sources: Maybe<&2,List<&2,Endpoint.AddressLookup>>) -> IO(Unit):
  do IO<Unit>:
    ticket : Maybe<&2,Tickets.EndpointTicket> <- Tickets.decode(text)
    lookup(ticket,sources)
