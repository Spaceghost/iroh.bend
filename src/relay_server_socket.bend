import Base

type ServerSocket is Type:
  RelayListener{id: U32}

type SocketEvent is Data:
  RelayIdle{}
  RelayJoined{id: U32, version: U32}
  RelayBytes{id: U32, bytes: List<&2,U32>}
  RelayLeft{id: U32}

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

def relay_export_keying_material(server: ServerSocket, id: U32, key: List<&2,U32>)
    -> IO(ServerSocket & Maybe<&1,List<&2,U32>>):
  import "./relay_server_socket.c"
