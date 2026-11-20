import Base

type ServerSocket is Type:
  RelayListener{id: U32}

type SocketEvent is Data:
  RelayIdle{}
  RelayJoined{id: U32, version: U32}
  RelayBytes{id: U32, bytes: List<&2,U32>}
  RelayRead{id: U32, wire_bytes: U32}
  RelayLeft{id: U32}

type RequestHeaderValues is Data:
  HeaderValues{values: List<&2,List<&2,U32>>}
  RepeatedCustomHeader{}

type RequestHeader is Data:
  HeaderField{name: List<&2,U32>, values: RequestHeaderValues}

type RequestFields is Data:
  Fields{authorization: List<&2,List<&2,U32>>, query: List<&2,List<&2,U32>>}
  FieldsWithHeaders{authorization: List<&2,List<&2,U32>>, query: List<&2,List<&2,U32>>,
    headers: List<&2,RequestHeader>}

type RequestDetails is Data:
  Details{path: List<&2,U32>, fields: RequestFields}
  MissingDetails{}

# An empty certificate and key select plaintext WS.
def relay_bind(host: String, port: U32, cert: String, key: String)
    -> IO(Result<&1,&1,U32 & String,ServerSocket & U32>):
  import "./relay_server_socket.c"

def relay_poll(server: ServerSocket) -> IO(ServerSocket & SocketEvent):
  import "./relay_server_socket.c"

def relay_millis() -> IO(U32):
  import "./relay_server_socket.c"

def relay_queue(server: ServerSocket, id: U32, bytes: List<&2,U32>)
    -> IO(ServerSocket & Bool):
  import "./relay_server_socket.c"

def relay_authorized(server: ServerSocket, id: U32) -> IO(ServerSocket):
  relay_authorized_with_meter(server,id,False{})

def relay_authorized_with_meter(server: ServerSocket, id: U32, metered: Bool) -> IO(ServerSocket):
  import "./relay_server_socket.c"

def relay_meter_challenge(server: ServerSocket, id: U32, metered: Bool) -> IO(ServerSocket):
  import "./relay_server_socket.c"

def relay_resume_rx(server: ServerSocket, id: U32) -> IO(ServerSocket):
  import "./relay_server_socket.c"

def relay_reconfigure_rx(server: ServerSocket, metered: Bool) -> IO(ServerSocket):
  import "./relay_server_socket.c"

# flush=1 closes after queued frames have been written.
def relay_kick(server: ServerSocket, id: U32, flush: U32) -> IO(ServerSocket):
  import "./relay_server_socket.c"

def relay_stop(server: ServerSocket) -> IO(Unit):
  import "./relay_server_socket.c"

def relay_nonce() -> IO(Result<&1,&1,U32 & String,List<&2,U32>>):
  import "./relay_server_socket.c"

def relay_client_auth_header(server: ServerSocket, id: U32)
    -> IO(ServerSocket & Maybe<&1,List<&2,U32>>):
  import "./relay_server_socket.c"

def relay_request_raw(server: ServerSocket, id: U32)
    -> IO(ServerSocket & List<&2,List<&2,List<&2,U32>>>):
  import "./relay_server_socket.c"

def drop_header_whitespace(bytes: List<&2,U32>) -> List<&2,U32>:
  match bytes:
    case Con{32,tail}:
      drop_header_whitespace(tail)
    case Con{9,tail}:
      drop_header_whitespace(tail)
    case _:
      bytes

def header_value(bytes: List<&2,U32>) -> List<&2,U32>:
  leading_trimmed = drop_header_whitespace(bytes)
  reversed = List.reverse(&2,U32,leading_trimmed)
  List.reverse(&2,U32,drop_header_whitespace(reversed))

def header_values(values: List<&2,List<&2,U32>>) -> List<&2,List<&2,U32>>:
  match values:
    case Con{value,rest}:
      Con{header_value(value),header_values(rest)}
    case Nil{}:
      []

def decoded_headers(raw: List<&2,List<&2,List<&2,U32>>>) -> List<&2,RequestHeader>:
  match raw:
    case Nil{}:
      []
    case Con{Con{name,Con{[0],values}},rest}:
      Con{HeaderField{name,HeaderValues{header_values(values)}},decoded_headers(rest)}
    case Con{[name,[1]],rest}:
      Con{HeaderField{name,RepeatedCustomHeader{}},decoded_headers(rest)}
    case Con{_,rest}:
      decoded_headers(rest)

def request_details(raw: List<&2,List<&2,List<&2,U32>>>) -> RequestDetails:
  match raw:
    case [[path],authorization,query]:
      Details{path,Fields{authorization,query}}
    case Con{[path],Con{authorization,Con{query,headers}}}:
      Details{path,FieldsWithHeaders{authorization,query,decoded_headers(headers)}}
    case _:
      MissingDetails{}

def request_result(raw: ServerSocket & List<&2,List<&2,List<&2,U32>>>) -> ServerSocket & RequestDetails:
  (socket,fields) = raw
  (socket,request_details(fields))

def relay_request_details(server: ServerSocket, id: U32) -> IO(ServerSocket & RequestDetails):
  do IO<ServerSocket & RequestDetails>:
    raw : ServerSocket & List<&2,List<&2,List<&2,U32>>> <- relay_request_raw(server,id)
    return request_result(raw)

def relay_enable_request_details(server: ServerSocket) -> IO(ServerSocket):
  import "./relay_server_socket.c"

def relay_export_keying_material(server: ServerSocket, id: U32, key: List<&2,U32>)
    -> IO(ServerSocket & Maybe<&1,List<&2,U32>>):
  import "./relay_server_socket.c"
