import Base
import ../src/relay.bend as Wire
import ../src/relay_client.bend as Client

def peer() -> List<&2,U32>:
  [25,127,107,35,225,108,133,50,198,171,200,56,250,205,94,167,
   137,190,12,118,178,146,3,52,3,155,250,139,61,54,141,97]

def source() -> List<&2,U32>:
  [119,44,138,68,43,125,176,110,22,108,251,193,204,188,188,222,
   111,62,186,118,164,233,142,243,255,197,25,80,34,55,214,239]

def payload() -> List<&2,U32>:
  [0,255,42]

def equal(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(x,y) && equal(xs,ys)
    case _ _:
      False{}

def matches(packet: Wire.Packet) -> Bool:
  match packet:
    case Wire.Datagram{from,ecn,segment,bytes}:
      equal(from,source()) && equal(bytes,payload()) && U32.is_eq(ecn,3) && U32.is_eq(segment,0)
    case _:
      False{}

def result(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("PASS two Rust-free clients authenticated and exchanged a datagram through Iroh relay")
    case False{}:
      IO.die(Unit,1,"relay did not forward the expected authenticated datagram")

def complete(reply: Client.Connection & Wire.Frame, sender: Client.Connection) -> IO(Unit):
  (receiver, frame) = reply
  do IO<Unit>:
    Client.close(sender)
    Client.close(receiver)
    result(matches(Wire.packet(frame)))

def test(+url: String, +max_version: U32) -> IO(Unit):
  do IO<Unit>:
    receiver : Client.Connection <- IO.try(Client.Connection, Client.connect_with_version(url, List.replicate(U32,32n,42), max_version))
    sender : Client.Connection <- IO.try(Client.Connection, Client.connect_with_version(url, List.replicate(U32,32n,73), max_version))
    sent : Client.Connection <- IO.try(Client.Connection, Client.send_datagram(sender, peer(), 3, 0, payload()))
    got : Client.Connection & Wire.Frame <- IO.try(Client.Connection & Wire.Frame, Client.receive(receiver))
    complete(got, sent)

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{url,Nil{}}}:
      test(url, 2)
    case Con{_,Con{url,Con{_,Nil{}}}}:
      test(url, 1)
    case _:
      IO.die(Unit,2,"expected the ws:// or wss:// relay URL")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
