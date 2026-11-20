import Base
import ../src/relay_websocket.bend as Ws

def final_message(result: Ws.Read) -> Bool:
  match result:
    case Ws.Received{Ws.Binary{[1,2,3]},_,[]}:
      True{}
    case _:
      False{}

def pong_then_data(result: Ws.Read) -> Bool:
  match result:
    case Ws.Received{Ws.Pong{[]},next,rest}:
      final_message(Ws.receive(next,rest,128))
    case _:
      False{}

def ping_then_pong(result: Ws.Read) -> Bool:
  match result:
    case Ws.Received{Ws.Ping{[90]},next,rest}:
      pong_then_data(Ws.receive(next,rest,128))
    case _:
      False{}

def continue_fragment(result: Ws.Read) -> Bool:
  match result:
    case Ws.Waiting{next}:
      ping_then_pong(Ws.receive(next,[4,0,0,0,5,137,129,8,1,0,0,82,138,128,0,0,0,0,
        128,130,9,7,0,0,11,4],128))
    case _:
      False{}

def failed(result: Ws.Read, status: U32) -> Bool:
  match result:
    case Ws.Rejected{actual}:
      U32.is_eq(actual,status)
    case _:
      False{}

def long_message(result: Ws.Read, expected: U32) -> Bool:
  match result:
    case Ws.Received{Ws.Binary{bytes},_,[]}:
      U32.is_eq(U32.from_nat(List.length(&2,U32,bytes)),expected)
    case _:
      False{}

def rotated_mask(result: Ws.Read) -> Bool:
  match result:
    case Ws.Received{Ws.Binary{[1,2,3,4,1,2,3,4,1]},_,[]}:
      True{}
    case _:
      False{}

def close(result: Ws.Read) -> Bool:
  match result:
    case Ws.Received{Ws.CloseFrame{[3,232,195,169]},_,[]}:
      True{}
    case _:
      False{}

def text_message(result: Ws.Read) -> Bool:
  match result:
    case Ws.Received{Ws.TextFrame{[195,169]},next,rest}:
      final_message(Ws.receive(next,rest,128))
    case _:
      False{}

def encoded(short: Maybe<&2,List<&2,U32>>, close: Maybe<&2,List<&2,U32>>, bad: Maybe<&2,List<&2,U32>>,
    medium: Maybe<&2,List<&2,U32>>) -> Bool:
  match short close bad medium:
    case Some{[138,2,0,255]} Some{[136,2,3,232]} None{} Some{Con{130,Con{126,Con{0,Con{126,_}}}}}:
      True{}
    case _ _ _ _:
      False{}

def checked(value: Bool) -> IO(Unit):
  match value:
    case True{}:
      IO.print("PASS WebSocket framing across reads, interleaved control frames, close status, and size limits")
    case False{}:
      IO.die(Unit,1,"WebSocket framing differed")

def main() -> IO(Unit):
  checked(
    encoded(Ws.encode(Ws.Pong{[0,255]}),Ws.encode(Ws.CloseFrame{[3,232]}),
      Ws.encode(Ws.Ping{List.replicate(U32,126n,0)}),
      Ws.encode(Ws.Binary{List.replicate(U32,126n,0)})) &&
    text_message(Ws.receive(Ws.decoder(),[1,129,0,0,0,0,195,128,129,0,0,0,0,169,
      130,131,0,0,0,0,1,2,3],128)) &&
    failed(Ws.receive(Ws.decoder(),[129,129,0,0,0,0,255],128),1007) &&
    continue_fragment(Ws.receive(Ws.decoder(),[2,129],128)) &&
    close(Ws.receive(Ws.decoder(),[136,132,1,2,3,4,2,234,192,173],128)) &&
    rotated_mask(Ws.receive(Ws.decoder(),[130,137,1,2,3,4,0,0,0,0,0,0,0,0,0],128)) &&
    failed(Ws.receive(Ws.decoder(),[136,129,0,0,0,0,3],128),1002) &&
    failed(Ws.receive(Ws.decoder(),[136,131,0,0,0,0,3,232,255],128),1007) &&
    failed(Ws.receive(Ws.decoder(),[130,0],128),1002) &&
    failed(Ws.receive(Ws.decoder(),[194],128),1002) &&
    failed(Ws.receive(Ws.decoder(),[0],128),1002) &&
    failed(Ws.receive(Ws.decoder(),[9],128),1002) &&
    failed(Ws.receive(Ws.decoder(),[137,254],128),1002) &&
    failed(Ws.receive(Ws.decoder(),[130,254,0,125],128),1002) &&
    failed(Ws.receive(Ws.decoder(),[130,255,128],65544),1002) &&
    failed(Ws.receive(Ws.decoder(),[130,255,0,0,0,0,0,1,0,0],65535),1009) &&
    failed(Ws.receive(Ws.decoder(),[2,129,0,0,0,0,0,128,129,0,0,0,0,0],1),1009) &&
    long_message(Ws.receive(Ws.decoder(),List.append(&2,U32,[130,254,0,126,0,0,0,0],
      List.replicate(U32,126n,0)),128),126) &&
    long_message(Ws.receive(Ws.decoder(),List.append(&2,U32,[130,255,0,0,0,0,0,1,0,0,1,2,3,4],
      List.replicate(U32,65536n,0)),65544),65536))
