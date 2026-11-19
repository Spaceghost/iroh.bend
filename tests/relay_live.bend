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

def test_token(+url: String, receiver_version: U32, sender_version: U32, +token: Maybe<&2,String>) -> IO(Unit):
  do IO<Unit>:
    receiver : Client.Connection <- IO.try(Client.Connection,
      Client.connect_with_token(url,List.replicate(U32,32n,42),receiver_version,token))
    sender : Client.Connection <- IO.try(Client.Connection,
      Client.connect_with_token(url,List.replicate(U32,32n,73),sender_version,token))
    sent : Client.Connection <- IO.try(Client.Connection, Client.send_datagram(sender, peer(), 3, 0, payload()))
    got : Client.Connection & Wire.Frame <- IO.try(Client.Connection & Wire.Frame, Client.receive(receiver))
    complete(got, sent)

def test(url: String, receiver_version: U32, sender_version: U32) -> IO(Unit):
  test_token(url,receiver_version,sender_version,None{})

def checked(conn: Client.Connection, ok: Bool) -> IO(Client.Connection):
  match ok:
    case True{}:
      IO.pure(Client.Connection,conn)
    case False{}:
      IO.die(Client.Connection,1,"relay delivered an unexpected lifecycle frame")

def matches_frame(frame: Wire.Frame, tag: U32, bytes: List<&2,U32>) -> Bool:
  match frame:
    case Wire.Message{kind,payload}:
      U32.is_eq(kind,tag) && equal(payload,bytes)
    case _:
      False{}

def check_frame(received: Client.Connection & Wire.Frame, tag: U32, bytes: List<&2,U32>) -> IO(Client.Connection):
  (next,frame) = received
  checked(next,matches_frame(frame,tag,bytes))

def expect(conn: Client.Connection, tag: U32, bytes: List<&2,U32>) -> IO(Client.Connection):
  do IO<Client.Connection>:
    response : Client.Connection & Wire.Frame <- IO.try(Client.Connection & Wire.Frame,Client.receive(conn))
    check_frame(response,tag,bytes)

def forward_to(sender: Client.Connection, receiver: Client.Connection, dest: List<&2,U32>,
    from: List<&2,U32>) -> IO(Client.Connection & Client.Connection):
  do IO<Client.Connection & Client.Connection>:
    sent : Client.Connection <- IO.try(Client.Connection,Client.send_datagram(sender,dest,0,0,payload()))
    got : Client.Connection <- expect(receiver,6,List.append(&2,U32,from,Con{0,payload()}))
    return (sent,got)

def text_bytes(chars: List<&2,Char>) -> List<&2,U32>:
  match chars:
    case Nil{}:
      []
    case Con{c,rest}:
      Con{Char.to_u32(c),text_bytes(rest)}

def final_departure(recovered: Client.Connection & Client.Connection) -> IO(Unit):
  (recipient,last) = recovered
  do IO<Unit>:
    Client.close(last)
    notified : Client.Connection <- expect(recipient,8,peer())
    Client.close(notified)
    IO.print("PASS relay routes to the active session, promotes a duplicate, and notifies the recipient on final departure")

def recovery(outbound: Client.Connection & Client.Connection, inactive: Client.Connection, status_tag: U32,
    healthy: List<&2,U32>) -> IO(Unit):
  (leaving,waiting) = outbound
  do IO<Unit>:
    Client.close(leaving)
    restored : Client.Connection <- expect(inactive,status_tag,healthy)
    barrier : Client.Connection <- IO.try(Client.Connection,Client.send_datagram(waiting,source(),0,0,payload()))
    observer : Client.Connection <- expect(barrier,6,List.append(&2,U32,source(),Con{0,payload()}))
    recovered : Client.Connection & Client.Connection <- forward_to(observer,restored,peer(),source())
    final_departure(recovered)

def record_delivery(incoming: Client.Connection & Client.Connection, inactive: Client.Connection,
    status_tag: U32, healthy: List<&2,U32>) -> IO(Unit):
  (watcher,active) = incoming
  do IO<Unit>:
    outbound : Client.Connection & Client.Connection <- forward_to(active,watcher,source(),peer())
    recovery(outbound,inactive,status_tag,healthy)

def lifecycle(+url: String, +version: U32, +status_tag: U32, standby: List<&2,U32>,
    healthy: List<&2,U32>) -> IO(Unit):
  do IO<Unit>:
    old : Client.Connection <- IO.try(Client.Connection,
      Client.connect_with_version(url,List.replicate(U32,32n,42),version))
    recent : Client.Connection <- IO.try(Client.Connection,
      Client.connect_with_version(url,List.replicate(U32,32n,42),version))
    observer : Client.Connection <- IO.try(Client.Connection,Client.connect(url,List.replicate(U32,32n,73)))
    inactive : Client.Connection <- expect(old,status_tag,standby)
    incoming : Client.Connection & Client.Connection <- forward_to(observer,recent,peer(),source())
    record_delivery(incoming,inactive,status_tag,healthy)

def duplicate(url: String) -> IO(Unit):
  lifecycle(url,2,13,[1],[0])

def duplicate_v1(url: String) -> IO(Unit):
  lifecycle(url,1,11,
    text_bytes(String.to_list("Another endpoint connected with the same endpoint id. No more messages will be received.")),
    text_bytes(String.to_list("The connection is healthy and has recovered from previous problems")))

def require_closed(closed: Result<&1,&1,U32 & String,Client.Connection & Wire.Frame>) -> IO(Unit):
  match closed:
    case Fail{_}:
      IO.pure(Unit,Unit{})
    case Done{_}:
      IO.die(Unit,1,"relay kept the connection with an unmatched pong")

def answer_payload(nonce: List<&2,U32>, correct: Bool) -> List<&2,U32>:
  match nonce correct:
    case Con{head,tail} False{}:
      Con{U32.xor(head,1),tail}
    case _ _:
      nonce

def answer_ping_frame(conn: Client.Connection, frame: Wire.Frame, correct: Bool) -> IO(Client.Connection):
  match frame:
    case Wire.Message{9,nonce}:
      IO.try(Client.Connection,Client.pong(conn,answer_payload(nonce,correct)))
    case _:
      IO.die(Client.Connection,1,"expected relay keepalive ping")

def answer_ping(message: Client.Connection & Wire.Frame, correct: Bool) -> IO(Client.Connection):
  (conn,frame) = message
  answer_ping_frame(conn,frame,correct)

def heartbeat(+url: String) -> IO(Unit):
  do IO<Unit>:
    live : Client.Connection <- IO.try(Client.Connection,Client.connect(url,List.replicate(U32,32n,42)))
    silent : Client.Connection <- IO.try(Client.Connection,Client.connect(url,List.replicate(U32,32n,73)))
    live_probe : Client.Connection & Wire.Frame <- IO.try(Client.Connection & Wire.Frame,Client.receive(live))
    replied : Client.Connection <- answer_ping(live_probe,True{})
    silent_probe : Client.Connection & Wire.Frame <- IO.try(Client.Connection & Wire.Frame,Client.receive(silent))
    mismatched : Client.Connection <- answer_ping(silent_probe,False{})
    lost : Result<&1,&1,U32 & String,Client.Connection & Wire.Frame> <- Client.receive(mismatched)
    require_closed(lost)
    sent : Client.Connection <- IO.try(Client.Connection,Client.send_datagram(replied,peer(),0,0,payload()))
    kept : Client.Connection <- expect(sent,6,List.append(&2,U32,peer(),Con{0,payload()}))
    Client.close(kept)
    IO.print("PASS relay keepalive accepts the matching pong and closes the connection with a mismatched pong")

def rate_payload() -> List<&2,U32>:
  List.replicate(U32,80n,42)

def rate_notice(sender: Client.Connection, version: U32) -> IO(Client.Connection):
  match version:
    case 1:
      IO.pure(Client.Connection,sender)
    case _:
      expect(sender,13,[2])

def elapsed_limit(elapsed: Bool) -> IO(Unit):
  match elapsed:
    case True{}:
      IO.pure(Unit,Unit{})
    case False{}:
      IO.die(Unit,1,"rate-limited datagrams arrived before the next refill")

def send_rate_frame(sender: Client.Connection) -> IO(Client.Connection):
  IO.try(Client.Connection,Client.send_datagram(sender,peer(),0,0,rate_payload()))

def finish_rate(sender: Client.Connection, receiver: Client.Connection, started: Nat) -> IO(Unit):
  do IO<Unit>:
    finished : Nat <- IO.now()
    elapsed_limit(Nat.is_ge(finished,Nat.add(750n,started)))
    returning : Client.Connection <- IO.try(Client.Connection,Client.send_datagram(receiver,source(),0,0,payload()))
    confirmed : Client.Connection <- expect(sender,6,List.append(&2,U32,peer(),Con{0,payload()}))
    Client.close(returning)
    Client.close(confirmed)
    IO.print("PASS relay throttled and resumed datagrams with the expected rate-limit notice")

def rate_exchange(sender: Client.Connection, receiver: Client.Connection, version: U32) -> IO(Unit):
  +frame = List.append(&2,U32,source(),Con{0,rate_payload()})
  do IO<Unit>:
    started : Nat <- IO.now()
    first : Client.Connection <- send_rate_frame(sender)
    second : Client.Connection <- send_rate_frame(first)
    third : Client.Connection <- send_rate_frame(second)
    noticed : Client.Connection <- rate_notice(third,version)
    arrived : Client.Connection <- expect(receiver,6,frame)
    received : Client.Connection <- expect(arrived,6,frame)
    drained : Client.Connection <- expect(received,6,frame)
    finish_rate(noticed,drained,started)

# Wait for each delivery before writing again so an upstream transport read
# cannot coalesce the three writes into a single charge.
def paced_rate_exchange(sender: Client.Connection, receiver: Client.Connection) -> IO(Unit):
  +frame = List.append(&2,U32,source(),Con{0,rate_payload()})
  do IO<Unit>:
    started : Nat <- IO.now()
    first : Client.Connection <- send_rate_frame(sender)
    noticed : Client.Connection <- rate_notice(first,2)
    arrived : Client.Connection <- expect(receiver,6,frame)
    second : Client.Connection <- send_rate_frame(noticed)
    received : Client.Connection <- expect(arrived,6,frame)
    last : Client.Connection <- send_rate_frame(second)
    drained : Client.Connection <- expect(received,6,frame)
    finish_rate(last,drained,started)

def test_paced_rate(+url: String) -> IO(Unit):
  do IO<Unit>:
    receiver : Client.Connection <- IO.try(Client.Connection,Client.connect(url,List.replicate(U32,32n,42)))
    sender : Client.Connection <- IO.try(Client.Connection,Client.connect(url,List.replicate(U32,32n,73)))
    paced_rate_exchange(sender,receiver)

def test_rate(+url: String, +version: U32) -> IO(Unit):
  do IO<Unit>:
    receiver : Client.Connection <- IO.try(Client.Connection,Client.connect(url,List.replicate(U32,32n,42)))
    sender : Client.Connection <- IO.try(Client.Connection,
      Client.connect_with_version(url,List.replicate(U32,32n,73),version))
    rate_exchange(sender,receiver,version)

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{url,Nil{}}}:
      test(url, 2, 2)
    case Con{_,Con{url,Con{"duplicate",Nil{}}}}:
      duplicate(url)
    case Con{_,Con{url,Con{"duplicate-v1",Nil{}}}}:
      duplicate_v1(url)
    case Con{_,Con{url,Con{"heartbeat",Nil{}}}}:
      heartbeat(url)
    case Con{_,Con{url,Con{"rate",Nil{}}}}:
      test_rate(url,2)
    case Con{_,Con{url,Con{"rate-v1",Nil{}}}}:
      test_rate(url,1)
    case Con{_,Con{url,Con{"rate-paced",Nil{}}}}:
      test_paced_rate(url)
    case Con{_,Con{url,Con{"bearer",Nil{}}}}:
      test_token(url,2,2,Some{"allow"})
    case Con{_,Con{url,Con{"bearer-denied",Nil{}}}}:
      test_token(url,1,1,Some{"deny"})
    case Con{_,Con{url,Con{"bearer-invalid",Nil{}}}}:
      test_token(url,2,2,Some{"bad\nvalue"})
    case Con{_,Con{url,Con{"mixed",Nil{}}}}:
      test(url, 1, 2)
    case Con{_,Con{url,Con{_,Nil{}}}}:
      test(url, 1, 1)
    case _:
      IO.die(Unit,2,"expected the ws:// or wss:// relay URL")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
