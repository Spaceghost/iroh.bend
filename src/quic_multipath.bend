import Base

type MultipathConnection is Type:
  MultipathConnection{id: U32}

type MultipathRead is Data:
  MultipathReadPending{}
  MultipathReadFin{}
  MultipathReadBytes{bytes: List<&2,U32>}

def start_multipath(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: String)
    -> IO(Result<&1,&1,U32 & String,MultipathConnection>):
  import "./quic_multipath.c"

# Drive pending network and timer work. 0 means handshaking, 1 means ready
# with base QUIC, and 2 means the peer negotiated multipath.
def step_multipath(conn: MultipathConnection)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

# Port zero chooses a free local port. None means retry after stepping.
# A returned path ID can be used after its state becomes available.
def probe_multipath(conn: MultipathConnection, bind_host: String, bind_port: U32, peer: String, peer_port: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>):
  import "./quic_multipath.c"

# Path 0 is the initial path. States are 0 probing, 1 available,
# 2 suspended, and 3 retired.
def multipath_status(conn: MultipathConnection, path: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

# Direction zero is bidirectional. Direction one is send-only.
def open_multipath_stream(conn: MultipathConnection, direction: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>):
  import "./quic_multipath.c"

def assign_stream_path(conn: MultipathConnection, stream: U32, path: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

def clear_stream_path(conn: MultipathConnection, stream: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  assign_stream_path(conn,stream,4294967295)

# Queue up to 64 KiB. Pass 1 for FIN. A zero result means retry after stepping.
def write_multipath_stream(conn: MultipathConnection, stream: U32, bytes: List<&2,U32>, fin: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

def read_multipath_stream(conn: MultipathConnection, stream: U32, limit: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,MultipathRead>):
  import "./quic_multipath.c"

def drop_multipath_stream(conn: MultipathConnection, stream: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

def close_multipath(conn: MultipathConnection) -> IO(Unit):
  import "./quic_multipath.c"

def ConnectResult() -> Type:
  Result<&1,&1,U32 & String,MultipathConnection>

def close_with_error(conn: MultipathConnection, error: U32 & String) -> IO(ConnectResult()):
  do IO<ConnectResult()>:
    close_multipath(conn)
    return Fail{error}

def handshake_progress(progress: MultipathConnection & Result<&1,&1,U32 & String,U32>,
    retry: MultipathConnection -> IO(ConnectResult())) -> IO(ConnectResult()):
  match progress:
    case (conn,Done{2}):
      IO.pure(ConnectResult(),Done{conn})
    case (conn,Done{0}):
      do IO<ConnectResult()>:
        IO.sleep(1)
        retry(conn)
    case (conn,Done{_}):
      close_with_error(conn,(95,"peer did not negotiate QUIC multipath"))
    case (conn,Fail{error}):
      close_with_error(conn,error)

def handshake_step(conn: MultipathConnection, expired: Bool,
    retry: MultipathConnection -> IO(ConnectResult())) -> IO(ConnectResult()):
  match expired:
    case True{}:
      close_with_error(conn,(110,"QUIC multipath handshake timed out"))
    case False{}:
      do IO<ConnectResult()>:
        progress : MultipathConnection & Result<&1,&1,U32 & String,U32> <- step_multipath(conn)
        handshake_progress(progress,retry)

def poll_handshake(fuel: Nat, conn: MultipathConnection, +deadline: Nat) -> IO(ConnectResult()):
  match fuel:
    case 0n:
      close_with_error(conn,(110,"QUIC multipath handshake timed out"))
    case 1n+left:
      do IO<ConnectResult()>:
        now : Nat <- IO.now()
        handshake_step(conn,Nat.is_ge(now,deadline),next => poll_handshake(left,next,deadline))

def finish_connect(started: ConnectResult(), +timeout_ms: Nat) -> IO(ConnectResult()):
  match started:
    case Done{conn}:
      do IO<ConnectResult()>:
        start : Nat <- IO.now()
        poll_handshake(Nat.add(timeout_ms,1n),conn,Nat.add(start,timeout_ms))
    case Fail{error}:
      IO.pure(ConnectResult(),Fail{error})

# Dial and require peer multipath negotiation before returning the connection.
def connect_multipath(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: String, timeout_ms: Nat) -> IO(ConnectResult()):
  do IO<ConnectResult()>:
    started : ConnectResult() <- start_multipath(host,port,seed,peer,alpn)
    finish_connect(started,timeout_ms)
