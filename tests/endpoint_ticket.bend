import Base
import ../src/endpoint_ticket.bend as Tickets
import ../src/endpoint_id.bend as Id

def display(value: Maybe<&2,String>) -> String:
  match value:
    case Some{text}:
      text
    case None{}:
      "invalid"

def canonical(value: Maybe<&2,Tickets.EndpointTicket>) -> String:
  match value:
    case Some{ticket}:
      display(Tickets.encode(ticket))
    case None{}:
      "invalid"

def assert_result(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.pure(Unit,Unit{})
    case False{}:
      IO.die(Unit,1,"unexpected endpoint ticket")

def assert_ticket(text: String, expected: String) -> IO(Unit):
  do IO<Unit>:
    got : Maybe<&2,Tickets.EndpointTicket> <- Tickets.decode(text)
    assert_result(String.eq(canonical(got),expected))

def golden() -> String:
  "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmaqacbuhi5dqhixs6zdfojyc43lffyxqcad7aaaadaai"

def mixed() -> String:
  "endpointacxfr74igmsbvsbnn73wcecg5vt3kbzncqwfrdiampuufwnhkublmbaaenuhi5dqom5c6l3smvwgc6jngaxgk6dbnvygyzjonzsxil3qmf2gqljrf4aqa7yaaaaokbybaeqacdnyaaaaaaaaaaaacaaaaaaokbyc77777777777777yba4aqcaibaeaqc"

def build_golden(key: Maybe<&2,List<&2,U32>>) -> String:
  match key:
    case None{}:
      "invalid"
    case Some{bytes}:
      +ip = {Tickets.IPv4{[127,0,0,1],1024} : Tickets.TransportAddress}
      relay = {Tickets.Relay{[104,116,116,112,58,47,47,100,101,114,112,46,109,101,46,47]} : Tickets.TransportAddress}
      display(Tickets.encode(Tickets.Ticket{bytes,[ip,relay,ip]}))

def vectors() -> IO(Unit):
  do IO<Unit>:
    assert_ticket(golden(),golden())
    assert_ticket(mixed(),mixed())
    assert_ticket("Endpointacxfr74i","invalid")
    assert_ticket("endpointaaaaaa","invalid")
    assert_ticket(String.append(golden(),"="),"invalid")
    assert_result(String.eq(build_golden(Id.decode("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")),golden()))
    IO.print("PASS Iroh endpoint ticket upstream snapshot, sorting and malformed inputs")

def print_tickets(inputs: List<String>) -> IO(Unit):
  match inputs:
    case Nil{}:
      IO.pure(Unit,Unit{})
    case Con{item,rest}:
      do IO<Unit>:
        ticket : Maybe<&2,Tickets.EndpointTicket> <- Tickets.decode(item)
        IO.print(canonical(ticket))
        print_tickets(rest)

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_]:
      vectors()
    case Con{_,rest}:
      print_tickets(rest)
    case _:
      vectors()

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
