import Base
import ./relay_http.bend as Http

def digest_accept(material: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,List<&2,U32>>):
  import "./relay_http_accept.c"

def protocol(version: U32) -> String:
  match version:
    case 1:
      "iroh-relay-v1"
    case _:
      "iroh-relay-v2"

def render(version: U32, accept: List<&2,U32>) -> List<&2,U32>:
  start : String = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n"
  List.append(&2,U32,Http.ascii(start ++ Http.security_headers() ++ "Sec-WebSocket-Accept: "),
    List.append(&2,U32,accept,Http.ascii("\r\nSec-WebSocket-Protocol: " ++ protocol(version) ++ "\r\n\r\n")))

# Encode the 101 for an UpgradeReady returned by the request parser.
def switching_protocols(+version: U32, nonce: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,List<&2,U32>>):
  do IO<Result<&1,&1,U32 & String,List<&2,U32>>>:
    accept : Result<&1,&1,U32 & String,List<&2,U32>> <- digest_accept(
      List.append(&2,U32,nonce,Http.ascii("258EAFA5-E914-47DA-95CA-C5AB0DC85B11")))
    return Result.map(&1,&1,U32 & String,List<&2,U32>,List<&2,U32>,key => render(version,key),accept)
