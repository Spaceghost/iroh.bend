import Base

type RelaySocket is Type:
  Connected{id: U32}

# Native WebSocket transport. Socket ownership transfers to each effect and
# is returned with its result. An I/O failure closes the underlying socket.
def open(url: String, max_version: U32) -> IO(Result<&1,&1,U32 & String, RelaySocket & U32>):
  import "./relay_socket.c"

def recv(socket: RelaySocket) -> IO(Result<&1,&1,U32 & String, RelaySocket & List<&2,U32>>):
  import "./relay_socket.c"

def send(socket: RelaySocket, bytes: List<&2,U32>) ->
    IO(Result<&1,&1,U32 & String, RelaySocket>):
  import "./relay_socket.c"

def close(socket: RelaySocket) -> IO(Unit):
  import "./relay_socket.c"
