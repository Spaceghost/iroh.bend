import Base
import ./relay_http.bend as Http

type Response is Data:
  HttpResponse{status: U32, headers: String, body: String}

type WireReply is Data:
  HttpReply{bytes: List<&2,U32>, persistent: Bool}

def text_chars(bytes: List<&2,U32>) -> List<&2,Char>:
  match bytes:
    case Nil{}:
      []
    case Con{byte,rest}:
      Con{Char.from_u32(byte),text_chars(rest)}

def text(bytes: List<&2,U32>) -> String:
  String.from_list(text_chars(bytes))

def challenge_char(+c: U32) -> Bool:
  Http.ascii_letter(c) || (U32.is_ge(c,48) && U32.is_le(c,57)) ||
  U32.is_eq(c,45) || U32.is_eq(c,46) || U32.is_eq(c,95)

def portal_header(challenge: List<&2,U32>, valid: Bool) -> String:
  match valid:
    case True{}:
      "X-Iroh-Response: response " ++ text(challenge) ++ "\r\n"
    case False{}:
      ""

def portal(fields: List<&2,List<&2,U32>>) -> String:
  match fields:
    case Con{Con{+first,+rest},_}:
      portal_header(Con{first,rest},Nat.is_lt(List.length(&2,U32,rest),63n) &&
        challenge_char(first) && List.all(&2,U32,byte => challenge_char(byte),rest))
    case _:
      ""

def index() -> Response:
  HttpResponse{200,"Content-Type: text/html; charset=utf-8\r\n",
    "<html><body><h1>Iroh Relay</h1><p><a href=\"https://iroh.computer/\">Iroh</a></p></body></html>"}

def route(method: String, target: String, tls: Bool, fields: List<&2,Http.HttpField>) -> Response:
  match method target tls:
    case "GET" "/" _:
      index()
    case "GET" "/index.html" _:
      index()
    case "GET" "/ping" _:
      HttpResponse{200,"Access-Control-Allow-Origin: *\r\n",""}
    case "GET" "/robots.txt" _:
      HttpResponse{200,"","User-agent: *\nDisallow: /\n"}
    case "GET" "/healthz" _:
      HttpResponse{200,"Content-Type: application/json\r\n",
        "{\"status\":\"ok\",\"version\":\"iroh.bend\",\"git_hash\":\"unknown\"}"}
    case "GET" "/generate_204" False{}:
      HttpResponse{204,portal(Http.values(fields,Http.ascii("x-iroh-challenge"))),""}
    case _ _ _:
      HttpResponse{404,"","Not Found"}

def reason(status: U32) -> String:
  match status:
    case 200:
      "200 OK"
    case 204:
      "204 No Content"
    case 404:
      "404 Not Found"
    case 431:
      "431 Request Header Fields Too Large"
    case 500:
      "500 Internal Server Error"
    case _:
      "400 Bad Request"

def protocol(version: U32) -> String:
  match version:
    case 10:
      "HTTP/1.0 "
    case _:
      "HTTP/1.1 "

def connection(version: U32, persistent: Bool) -> String:
  match version persistent:
    case _ False{}:
      "Connection: close\r\n"
    case 10 True{}:
      "Connection: keep-alive\r\n"
    case _ True{}:
      ""

def content_length(status: U32, size: U32) -> String:
  match status:
    case 204:
      ""
    case _:
      "Content-Length: " ++ U32.show(size) ++ "\r\n"

def payload(body: String, head: Bool) -> String:
  match head:
    case True{}:
      ""
    case False{}:
      body

def render(response: Response, +version: U32, +persistent: Bool, head: Bool) -> WireReply:
  HttpResponse{+status,headers,+body} = response
  HttpReply{Http.ascii(protocol(version) ++ reason(status) ++ "\r\n" ++ Http.security_headers() ++
    headers ++ connection(version,persistent) ++ content_length(status,U32.from_nat(String.length(body))) ++
    "\r\n" ++ payload(body,head)),persistent}

def persistence(version: U32, close: Bool, keep: Bool, empty: Bool) -> Bool:
  match version close keep empty:
    case _ True{} _ _:
      False{}
    case 11 False{} _ True{}:
      True{}
    case 10 False{} True{} True{}:
      True{}
    case _ _ _ _:
      False{}

def serve(request: Http.HttpRequest, tls: Bool) -> WireReply:
  Http.RequestHead{method,target,+version,+fields} = request
  +verb = text(method)
  +options = Http.values(fields,Http.ascii("connection"))
  keep = persistence(version,Http.contains_header_token(options,Http.ascii("close")),
    Http.contains_header_token(options,Http.ascii("keep-alive")),Http.permitted_body(fields))
  render(route(verb,text(Http.path(target)),tls,fields),version,keep,String.eq(verb,"HEAD"))

def rejection_header(version: Bool) -> String:
  match version:
    case True{}:
      "Sec-WebSocket-Version: 13\r\n"
    case False{}:
      ""

def rejected(status: U32, version: Bool) -> WireReply:
  render(HttpResponse{status,rejection_header(version),""},11,False{},False{})
