import Base

type DatagramConnection is Type:
  DatagramConnection{id: U32}

def start_quic_datagram(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,DatagramConnection>):
  import "./quic_datagram.c"

# Process one UDP input packet, timer expiry, and one outgoing packet.
# The result is 1 once the peer key and QUIC handshake are verified.
def step_quic_datagram(conn: DatagramConnection)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

# 1 means the QUIC stack accepted the datagram. 0 means retry after stepping.
# Acceptance does not imply delivery. The stack never retransmits the frame.
def write_quic_datagram(conn: DatagramConnection, payload: List<&2,U32>)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

# Retrieve one application datagram from the receive queue.
def read_quic_datagram(conn: DatagramConnection)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>):
  import "./quic_datagram.c"

# Count peer QUIC acknowledgments for packets carrying our datagrams.
def quic_datagram_acks(conn: DatagramConnection)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

def drop_quic_datagram(conn: DatagramConnection) -> IO(Unit):
  import "./quic_datagram.c"

def after_step(progress: DatagramConnection & Result<&1,&1,U32 & String,U32>, resume: DatagramConnection -> IO(Result<&1,&1,U32 & String,DatagramConnection>))
    -> IO(Result<&1,&1,U32 & String,DatagramConnection>):
  match progress:
    case (live,Done{1}):
      IO.pure(Result<&1,&1,U32 & String,DatagramConnection>,Done{live})
    case (next,Done{_}):
      do IO<Result<&1,&1,U32 & String,DatagramConnection>>:
        IO.sleep(1)
        resume(next)
    case (failed,Fail{error}):
      do IO<Result<&1,&1,U32 & String,DatagramConnection>>:
        drop_quic_datagram(failed)
        IO.pure(Result<&1,&1,U32 & String,DatagramConnection>,Fail{error})

def handshake_timeout(conn: DatagramConnection) -> IO(Result<&1,&1,U32 & String,DatagramConnection>):
  do IO<Result<&1,&1,U32 & String,DatagramConnection>>:
    drop_quic_datagram(conn)
    IO.pure(Result<&1,&1,U32 & String,DatagramConnection>,
      Fail{(110,"QUIC datagram handshake timed out")})

def until_ready(conn: DatagramConnection, expired: Bool,
    resume: DatagramConnection -> IO(Result<&1,&1,U32 & String,DatagramConnection>))
    -> IO(Result<&1,&1,U32 & String,DatagramConnection>):
  match expired:
    case True{}:
      handshake_timeout(conn)
    case False{}:
      do IO<Result<&1,&1,U32 & String,DatagramConnection>>:
        progress : DatagramConnection & Result<&1,&1,U32 & String,U32> <- step_quic_datagram(conn)
        after_step(progress,resume)

def handshake(fuel: Nat, conn: DatagramConnection, +deadline: Nat)
    -> IO(Result<&1,&1,U32 & String,DatagramConnection>):
  match fuel:
    case 0n:
      handshake_timeout(conn)
    case 1n+left:
      do IO<Result<&1,&1,U32 & String,DatagramConnection>>:
        now : Nat <- IO.now()
        until_ready(conn,Nat.is_ge(now,deadline),next => handshake(left,next,deadline))

def begin_handshake(started: Result<&1,&1,U32 & String,DatagramConnection>, +timeout_ms: Nat)
    -> IO(Result<&1,&1,U32 & String,DatagramConnection>):
  match started:
    case Done{conn}:
      do IO<Result<&1,&1,U32 & String,DatagramConnection>>:
        now : Nat <- IO.now()
        handshake(Nat.add(timeout_ms,1n),conn,Nat.add(now,timeout_ms))
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,DatagramConnection>,Fail{error})

# Dial a numeric IPv4 or IPv6 address with pinned Ed25519 keys and one ALPN.
def connect(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, timeout_ms: Nat) -> IO(Result<&1,&1,U32 & String,DatagramConnection>):
  do IO<Result<&1,&1,U32 & String,DatagramConnection>>:
    started : Result<&1,&1,U32 & String,DatagramConnection> <-
      start_quic_datagram(host,port,secret,peer,alpn)
    begin_handshake(started,timeout_ms)

type QuicStreamRead is Data:
  QuicStreamPending{}
  QuicStreamFin{}
  QuicStreamBytes{bytes: List<&2,U32>}

# Direction 0 is bidirectional. Direction 1 is unidirectional.
# Both functions return zero when no stream is available.
def open_quic_stream(conn: DatagramConnection, direction: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

def accept_quic_stream(conn: DatagramConnection, direction: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

# Queue up to 64 KiB. Pass 1 to finish the send half after these bytes.
# Zero means the previous write is awaiting acknowledgment.
def queue_quic_stream(conn: DatagramConnection, stream: U32, data: List<&2,U32>, finish: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

# Process one outbound packet. 1 means the write was submitted, including FIN
# when requested. Use step_quic_datagram to drive ACKs, retries, and timers.
def flush_quic_stream(conn: DatagramConnection, stream: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

def read_quic_stream(conn: DatagramConnection, stream: U32, limit: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,QuicStreamRead>):
  import "./quic_datagram.c"

# Release a completed stream. Dropping a live stream aborts its open halves.
def drop_quic_stream(conn: DatagramConnection, stream: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_datagram.c"
