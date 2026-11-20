import Base
import ../src/relay_http.bend as Http
import ../src/relay_http_accept.bend as Accept

def checked(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("PASS RFC 6455 accept digest and Iroh v2 switching response")
    case False{}:
      IO.die(Unit,1,"WebSocket 101 response differed")

def check(result: Http.UpgradeResult) -> IO(Unit):
  match result:
    case Http.UpgradeReady{version,key}:
      do IO<Unit>:
        reply : List<&2,U32> <- IO.try(List<&2,U32>,Accept.switching_protocols(version,key))
        checked(Http.equal(reply,Http.ascii(
          "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: upgrade\r\n" ++
          Http.security_headers() ++
          "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\nSec-WebSocket-Protocol: iroh-relay-v2\r\n\r\n")))
    case _:
      checked(False{})

def upgrade(result: Http.RequestRead) -> IO(Unit):
  match result:
    case Http.HeadRead{head,[]}:
      check(Http.request_upgrade(head))
    case _:
      checked(False{})

def main() -> IO(Unit):
  upgrade(Http.receive(Http.reader(),Http.ascii(
    "GET /relay HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: upgrade\r\n" ++
    "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" ++
    "Sec-WebSocket-Protocol: iroh-relay-v1, iroh-relay-v2\r\n\r\n")))
