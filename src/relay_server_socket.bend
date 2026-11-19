import Base

type ServerSocket is Type:
  RelayListener{id: U32}

type SocketEvent is Data:
  RelayIdle{}
  RelayJoined{id: U32, version: U32}
  RelayBytes{id: U32, bytes: List<&2,U32>}
  RelayLeft{id: U32}

type RequestFields is Data:
  Fields{authorization: List<&2,List<&2,U32>>, query: List<&2,List<&2,U32>>}

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

def request_details(raw: List<&2,List<&2,List<&2,U32>>>) -> RequestDetails:
  match raw:
    case [[path],authorization,query]:
      Details{path,Fields{authorization,query}}
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
