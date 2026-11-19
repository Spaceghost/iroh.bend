import Base

type RelaySocket is Type:
  Connected{id: U32}

type PendingUpgrade is Type:
  Pending{id: U32}

# Native WebSocket transport. Socket ownership transfers to each effect and
# is returned with its result. An I/O failure closes the underlying socket.
def open(url: String, max_version: U32) -> IO(Result<&1,&1,U32 & String, RelaySocket & U32>):
  import "./relay_socket.c"

# Holds the connection before its HTTP request when exporter material is
# available. Complete every successful preparation by calling upgrade.
def prepare(url: String, max_version: U32, key: List<&2,U32>) ->
    IO(Result<&1,&1,U32 & String,PendingUpgrade & Maybe<&1,List<&2,U32>>>):
  import "./relay_socket.c"

def upgrade(pending: PendingUpgrade, header: Maybe<&1,List<&2,U32>>) ->
    IO(Result<&1,&1,U32 & String,RelaySocket & (U32 & Bool)>):
  import "./relay_socket.c"

def recv(socket: RelaySocket) -> IO(Result<&1,&1,U32 & String, RelaySocket & List<&2,U32>>):
  import "./relay_socket.c"

def send(socket: RelaySocket, bytes: List<&2,U32>) ->
    IO(Result<&1,&1,U32 & String, RelaySocket>):
  import "./relay_socket.c"

def close(socket: RelaySocket) -> IO(Unit):
  import "./relay_socket.c"
