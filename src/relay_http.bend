import Base

# A request head ends at the empty CRLF line. The caller owns the transport
# and retains any bytes read after the head, including the first WS frame.
type HttpField is Data:
  HttpFieldValue{name: List<&2,U32>, value: List<&2,U32>}

type HttpRequest is Data:
  RequestHead{method: List<&2,U32>, target: List<&2,U32>, version: U32, fields: List<&2,HttpField>}

type RequestLine is Data:
  StartLine{method: List<&2,U32>, target: List<&2,U32>, version: U32}

type Head is Data:
  ReadingStart{}
  ReadingFields{start: RequestLine, fields: List<&2,HttpField>, slots: Nat}

type Reader is Data:
  HeadReader{head: Head, line: List<&2,U32>, cr: Bool, remaining: Nat}

type RequestRead is Data:
  AwaitingHead{reader: Reader}
  HeadRead{request: HttpRequest, remaining: List<&2,U32>}
  BadRequestHead{status: U32}

type HeadStep is Data:
  ReadMoreHead{reader: Reader}
  EndOfHead{request: HttpRequest}
  BadHead{status: U32}

def reader() -> Reader:
  HeadReader{ReadingStart{},[],False{},32768n}

def ascii_letter(+b: U32) -> Bool:
  (U32.is_ge(b,65) && U32.is_le(b,90)) || (U32.is_ge(b,97) && U32.is_le(b,122))

def token_char(+b: U32) -> Bool:
  ascii_letter(b) || (U32.is_ge(b,48) && U32.is_le(b,57)) ||
  U32.is_eq(b,33) || U32.is_eq(b,35) || U32.is_eq(b,36) || U32.is_eq(b,37) ||
  U32.is_eq(b,38) || U32.is_eq(b,39) || U32.is_eq(b,42) || U32.is_eq(b,43) ||
  U32.is_eq(b,45) || U32.is_eq(b,46) || U32.is_eq(b,94) || U32.is_eq(b,95) ||
  U32.is_eq(b,96) || U32.is_eq(b,124) || U32.is_eq(b,126)

def target_char(+b: U32) -> Bool:
  U32.is_ge(b,33) && U32.is_le(b,126) && Bool.not(U32.is_eq(b,35))

def field_char(+b: U32) -> Bool:
  U32.is_eq(b,9) || (U32.is_ge(b,32) && U32.is_le(b,255) && Bool.not(U32.is_eq(b,127)))

def bytes(chars: List<&2,Char>) -> List<&2,U32>:
  match chars:
    case Nil{}:
      []
    case Con{c,tail}:
      Con{Char.to_u32(c),bytes(tail)}

def ascii(text: String) -> List<&2,U32>:
  bytes(String.to_list(text))

def equal(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(x,y) && equal(xs,ys)
    case _ _:
      False{}

def lower_byte(+b: U32, upper: Bool) -> U32:
  match upper:
    case True{}:
      U32.add(b,32)
    case False{}:
      b

def lower(input: List<&2,U32>) -> List<&2,U32>:
  match input:
    case Nil{}:
      []
    case Con{+b,tail}:
      Con{lower_byte(b,U32.is_ge(b,65) && U32.is_le(b,90)),lower(tail)}

type SplitLine is Data:
  AtSeparator{left: List<&2,U32>, right: List<&2,U32>}
  NoSeparator{whole: List<&2,U32>}

def split_after(input: List<&2,U32>, +separator: U32, previous: U32, reversed: List<&2,U32>,
    found: Bool) -> SplitLine:
  match input found:
    case tail True{}:
      AtSeparator{List.reverse(&2,U32,reversed),tail}
    case Nil{} False{}:
      NoSeparator{List.reverse(&2,U32,Con{previous,reversed})}
    case Con{+b,tail} False{}:
      split_after(tail,separator,b,Con{previous,reversed},U32.is_eq(b,separator))

def split(input: List<&2,U32>, +separator: U32) -> SplitLine:
  match input:
    case Nil{}:
      NoSeparator{[]}
    case Con{+b,tail}:
      split_after(tail,separator,b,[],U32.is_eq(b,separator))

def drop_ows(input: List<&2,U32>) -> List<&2,U32>:
  match input:
    case Con{32,tail}:
      drop_ows(tail)
    case Con{9,tail}:
      drop_ows(tail)
    case _:
      input

def trim_ows(input: List<&2,U32>) -> List<&2,U32>:
  List.reverse(&2,U32,drop_ows(List.reverse(&2,U32,drop_ows(input))))

def version_number(version: List<&2,U32>) -> U32:
  match version:
    case [72,84,84,80,47,49,46,49]:
      11
    case [72,84,84,80,47,49,46,48]:
      10
    case _:
      0

def request_version(method: List<&2,U32>, +target: List<&2,U32>, +version: U32,
    remaining: Nat, tokens_valid: Bool) -> HeadStep:
  match target version tokens_valid:
    case Con{_,_} 0 _:
      BadHead{400}
    case Con{_,_} _ True{}:
      ReadMoreHead{HeadReader{ReadingFields{StartLine{method,target,version},[],100n},[],False{},remaining}}
    case _ _ _:
      BadHead{400}

def request_target(+method: List<&2,U32>, target: SplitLine, remaining: Nat) -> HeadStep:
  match method target:
    case Con{_,_} AtSeparator{+path,version}:
      request_version(method,path,version_number(version),remaining,
        List.all(&2,U32,b => token_char(b),method) && List.all(&2,U32,b => target_char(b),path))
    case _ _:
      BadHead{400}

def request_start(line: SplitLine, remaining: Nat) -> HeadStep:
  match line:
    case AtSeparator{method,tail}:
      request_target(method,split(tail,32),remaining)
    case _:
      BadHead{400}

def keep_field(+name: List<&2,U32>, value: List<&2,U32>, start: RequestLine, fields: List<&2,HttpField>,
    slots: Nat, remaining: Nat, valid: Bool) -> HeadStep:
  match name valid:
    case Con{_,_} True{}:
      entry : HttpField = HttpFieldValue{lower(name),trim_ows(value)}
      ReadMoreHead{HeadReader{ReadingFields{start,Con{entry,fields},slots},[],False{},remaining}}
    case _ _:
      BadHead{400}

def request_field(field: SplitLine, start: RequestLine, fields: List<&2,HttpField>, slots: Nat,
    remaining: Nat) -> HeadStep:
  match field:
    case AtSeparator{+name,+value}:
      keep_field(name,value,start,fields,slots,remaining,
        List.all(&2,U32,b => token_char(b),name) && List.all(&2,U32,b => field_char(b),value))
    case _:
      BadHead{400}

def complete(start: RequestLine, fields: List<&2,HttpField>) -> HeadStep:
  StartLine{method,target,version} = start
  EndOfHead{RequestHead{method,target,version,List.reverse(&2,HttpField,fields)}}

def end_line(head: Head, +line: List<&2,U32>, remaining: Nat) -> HeadStep:
  match head line:
    case ReadingStart{} _:
      request_start(split(List.reverse(&2,U32,line),32),remaining)
    case ReadingFields{start,fields,_} Nil{}:
      complete(start,fields)
    case ReadingFields{_,_,0n} _:
      BadHead{431}
    case ReadingFields{start,fields,1n+slots} Con{_,_}:
      request_field(split(List.reverse(&2,U32,line),58),start,fields,slots,remaining)

def push_byte(head: Head, line: List<&2,U32>, cr: Bool, remaining: Nat, +byte: U32, valid: Bool) -> HeadStep:
  match cr byte valid:
    case True{} 10 True{}:
      end_line(head,line,remaining)
    case False{} 13 True{}:
      ReadMoreHead{HeadReader{head,line,True{},remaining}}
    case _ _ False{}:
      BadHead{400}
    case True{} _ _:
      BadHead{400}
    case False{} 10 _:
      BadHead{400}
    case False{} _ True{}:
      ReadMoreHead{HeadReader{head,Con{byte,line},False{},remaining}}

def read_head(input: List<&2,U32>, next: HeadStep) -> RequestRead:
  match input next:
    case tail EndOfHead{request}:
      HeadRead{request,tail}
    case _ BadHead{status}:
      BadRequestHead{status}
    case Nil{} ReadMoreHead{state}:
      AwaitingHead{state}
    case Con{_,_} ReadMoreHead{HeadReader{_,_,_,0n}}:
      BadRequestHead{431}
    case Con{+b,tail} ReadMoreHead{HeadReader{head,line,cr,1n+remaining}}:
      read_head(tail,push_byte(head,line,cr,remaining,b,U32.is_le(b,255)))

def receive(state: Reader, bytes: List<&2,U32>) -> RequestRead:
  read_head(bytes,ReadMoreHead{state})

def field_match(tail: List<&2,List<&2,U32>>, value: List<&2,U32>, matched: Bool)
    -> List<&2,List<&2,U32>>:
  match matched:
    case True{}:
      Con{value,tail}
    case False{}:
      tail

def matching_fields(fields: List<&2,HttpField>, +name: List<&2,U32>) -> List<&2,List<&2,U32>>:
  match fields:
    case Nil{}:
      []
    case Con{HttpFieldValue{key,value},tail}:
      field_match(matching_fields(tail,name),value,equal(key,name))

# Lookups preserve every occurrence in arrival order, including empty values.
def values(fields: List<&2,HttpField>, name: List<&2,U32>) -> List<&2,List<&2,U32>>:
  matching_fields(fields,lower(name))

def path_only(parts: SplitLine) -> List<&2,U32>:
  match parts:
    case AtSeparator{path,_}:
      path
    case NoSeparator{path}:
      path

def path(target: List<&2,U32>) -> List<&2,U32>:
  path_only(split(target,63))

def target_query(parts: SplitLine) -> Maybe<&2,List<&2,U32>>:
  match parts:
    case AtSeparator{_,query}:
      Some{query}
    case _:
      None{}

def query(target: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  target_query(split(target,63))

type UpgradeResult is Data:
  OrdinaryRequest{}
  UpgradeReady{version: U32, nonce: List<&2,U32>}
  UpgradeRejected{status: U32}
  UnsupportedWebSocketVersion{}

def token_equal(reversed: List<&2,U32>, want: List<&2,U32>) -> Bool:
  equal(trim_ows(List.reverse(&2,U32,reversed)),want)

def contains_token(input: List<&2,U32>, +want: List<&2,U32>, reversed: List<&2,U32>) -> Bool:
  match input:
    case Nil{}:
      token_equal(reversed,want)
    case Con{44,tail}:
      token_equal(reversed,want) || contains_token(tail,want,[])
    case Con{b,tail}:
      contains_token(tail,want,Con{b,reversed})

def contains_header_token(fields: List<&2,List<&2,U32>>, +want: List<&2,U32>) -> Bool:
  match fields:
    case Nil{}:
      False{}
    case Con{value,tail}:
      contains_token(lower(value),want,[]) || contains_header_token(tail,want)

def zero_length(value: List<&2,U32>) -> Bool:
  match value:
    case Con{48,tail}:
      List.all(&2,U32,b => U32.is_eq(b,48),tail)
    case _:
      False{}

def no_body(transfer: List<&2,List<&2,U32>>, length: List<&2,List<&2,U32>>) -> Bool:
  match transfer length:
    case Nil{} Nil{}:
      True{}
    case Nil{} Con{value,Nil{}}:
      zero_length(value)
    case _ _:
      False{}

def permitted_body(+fields: List<&2,HttpField>) -> Bool:
  no_body(values(fields,ascii("transfer-encoding")),values(fields,ascii("content-length")))

def choose_version(nonce: List<&2,U32>, v2: Bool, v1: Bool) -> UpgradeResult:
  match v2 v1:
    case True{} _:
      UpgradeReady{2,nonce}
    case False{} True{}:
      UpgradeReady{1,nonce}
    case _ _:
      UpgradeRejected{400}

def websocket_upgrade(values: List<&2,List<&2,U32>>) -> Bool:
  match values:
    case [value]:
      equal(value,ascii("websocket"))
    case _:
      False{}

def requested_version(values: List<&2,List<&2,U32>>) -> U32:
  match values:
    case [[49,51]]:
      13
    case [_]:
      1
    case _:
      0

def check_upgrade(version: U32, nonces: List<&2,List<&2,U32>>, protocols: List<&2,List<&2,U32>>,
    valid: Bool) -> UpgradeResult:
  match version nonces protocols valid:
    case _ Con{Nil{},Nil{}} _ _:
      UpgradeRejected{400}
    case 13 Con{+nonce,Nil{}} Con{+offer,_} True{}:
      # Only the first subprotocol field is used by Iroh.
      choose_version(nonce,contains_token(offer,ascii("iroh-relay-v2"),[]),
        contains_token(offer,ascii("iroh-relay-v1"),[]))
    case 1 Con{_,Nil{}} _ True{}:
      UnsupportedWebSocketVersion{}
    case _ _ _ _:
      UpgradeRejected{400}

def decide_upgrade(method: List<&2,U32>, version: U32, +fields: List<&2,HttpField>,
    relay_path: Bool) -> UpgradeResult:
  match method version relay_path:
    case Con{71,Con{69,Con{84,Nil{}}}} 11 True{}:
      check_upgrade(requested_version(values(fields,ascii("sec-websocket-version"))),
        values(fields,ascii("sec-websocket-key")),
        values(fields,ascii("sec-websocket-protocol")),
        contains_header_token(values(fields,ascii("connection")),ascii("upgrade")) &&
        websocket_upgrade(values(fields,ascii("upgrade"))) && permitted_body(fields))
    case Con{71,Con{69,Con{84,Nil{}}}} _ True{}:
      UpgradeRejected{400}
    case _ _ _:
      OrdinaryRequest{}

def request_upgrade(req: HttpRequest) -> UpgradeResult:
  RequestHead{method,target,version,fields} = req
  +route = path(target)
  decide_upgrade(method,version,fields,equal(route,ascii("/relay")) || equal(route,ascii("/derp")))
