import Base
import ../src/relay_http.bend as Http
import ../src/relay_websocket.bend as Ws

def selected(res: Http.UpgradeResult) -> Bool:
  match res:
    case Http.UpgradeReady{2,key}:
      Http.equal(key,Http.ascii("dGhlIHNhbXBsZSBub25jZQ=="))
    case _:
      False{}

def values_ok(values: List<&2,List<&2,U32>>) -> Bool:
  match values:
    case [[111,110,101],[],[116,119,111]]:
      True{}
    case _:
      False{}

def query_ok(query: Maybe<&2,List<&2,U32>>) -> Bool:
  match query:
    case Some{value}:
      Http.equal(value,Http.ascii("token=a%26b"))
    case None{}:
      False{}

def first_frame(result: Ws.Read) -> Bool:
  match result:
    case Ws.Received{Ws.Binary{[]},_,[]}:
      True{}
    case _:
      False{}

def request_ok(result: Http.RequestRead) -> Bool:
  match result:
    case Http.HeadRead{Http.RequestHead{method,+target,11,+fields},remaining}:
      values_ok(Http.values(fields,Http.ascii("X-FiX"))) &&
      Http.equal(Http.path(target),Http.ascii("/relay")) && query_ok(Http.query(target)) &&
      selected(Http.request_upgrade(Http.RequestHead{method,target,11,fields})) &&
      first_frame(Ws.receive(Ws.decoder(),remaining,128))
    case _:
      False{}

def resume(result: Http.RequestRead) -> Bool:
  match result:
    case Http.AwaitingHead{reader}:
      head = "\nHost: localhost\r\nX-Fix:\tone\t\r\nx-fix:\r\nX-FIX: two\r\n" ++
        "Connection: keep-alive, UpGrAdE\r\nUpgrade: websocket\r\n" ++
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n" ++
        "Sec-WebSocket-Protocol: unknown, iroh-relay-v1, iroh-relay-v2\r\n\r\n"
      request_ok(Http.receive(reader,List.append(&2,U32,Http.ascii(head),[130,128,0,0,0,0])))
    case _:
      False{}

def bad_head(result: Http.RequestRead, status: U32) -> Bool:
  match result:
    case Http.BadRequestHead{actual}:
      U32.is_eq(actual,status)
    case _:
      False{}

def checked(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("PASS incremental relay HTTP upgrade and ordered repeated request headers")
    case False{}:
      IO.die(Unit,1,"HTTP upgrade validation differed")

def parse(input: String) -> Http.RequestRead:
  Http.receive(Http.reader(),Http.ascii(input))

def upgrade(input: Http.RequestRead) -> Http.UpgradeResult:
  match input:
    case Http.HeadRead{req,[]}:
      Http.request_upgrade(req)
    case _:
      Http.UpgradeRejected{0}

def open_request(version: String, extensions: String) -> Http.UpgradeResult:
  upgrade(parse("GET /relay HTTP/1.1\r\nHost: localhost\r\nConnection: upgrade\r\nUpgrade: websocket\r\n" ++
    "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: " ++ version ++
    "\r\nSec-WebSocket-Protocol: iroh-relay-v1\r\n" ++ extensions ++ "\r\n"))

def upgrade_cases(first: Http.UpgradeResult, version: Http.UpgradeResult,
    length: Http.UpgradeResult, transfer: Http.UpgradeResult, duplicate: Http.UpgradeResult) -> Bool:
  match first version length transfer duplicate:
    case Http.UpgradeReady{1,_} Http.UnsupportedWebSocketVersion{} Http.UpgradeRejected{400}
        Http.UpgradeRejected{400} Http.UpgradeRejected{400}:
      True{}
    case _ _ _ _ _:
      False{}

def excess_fields(count: Nat) -> String:
  match count:
    case 0n:
      "\r\n"
    case 1n+n:
      "X-Test:\r\n" ++ excess_fields(n)

def main() -> IO(Unit):
  checked(resume(parse("GET /relay?token=a%26b HTTP/1.1\r")) &&
    bad_head(parse("GET / HTTP/1.1\n\n"),400) &&
    bad_head(parse("GET / HTTP/1.1\r\nHost : host\r\n\r\n"),400) &&
    bad_head(parse("GET / HTTP/1.1\r\n: empty\r\n\r\n"),400) &&
    bad_head(parse("GET  HTTP/1.1\r\n\r\n"),400) &&
    bad_head(parse("GET / HTTP/1.1\r\n folded\r\n\r\n"),400) &&
    bad_head(parse("GET / HTTP/1.1\r\n" ++ excess_fields(101n)),431) &&
    bad_head(Http.receive(Http.reader(),List.replicate(U32,32769n,65)),431) &&
    upgrade_cases(open_request("13","Content-Length: 0\r\n"),open_request("12",""),
      open_request("13","Content-Length: 1\r\n"),open_request("13","Transfer-Encoding: chunked\r\n"),
      open_request("13","Sec-WebSocket-Key: duplicate\r\n")))
