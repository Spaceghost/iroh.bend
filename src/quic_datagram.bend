import Base
import ./quic_stream.bend as Stream
import ./quic_close.bend as Close
import ./quic_close_wire.bend as CloseWire
import ./quic_nat.bend as NatWire

type DatagramConnection is Type:
  DatagramConnection{id: U32}

def start_quic_datagram_with_idle_timeout(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>,
    idle_ms: NatWire.VarInt) -> IO(Result<&1,&1,U32 & String,DatagramConnection>):
  import "./quic_datagram.c"

def start_quic_datagram(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,DatagramConnection>):
  start_quic_datagram_with_idle_timeout(host,port,secret,peer,alpn,Close.default_idle_timeout())

# Initial route selection uses one ngtcp2/TLS session. Bend owns the connected
# UDP sockets until the socket carrying the authenticated handshake is adopted.
def start_route_handshake_with_idle_timeout(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>, alpn: List<&2,U32>,
    idle_ms: NatWire.VarInt) -> IO(Result<&1,&1,U32 & String,DatagramConnection & Socket>):
  import "./quic_datagram.c"

def start_route_handshake(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>, alpn: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,DatagramConnection & Socket>):
  start_route_handshake_with_idle_timeout(host,port,secret,peer,alpn,Close.default_idle_timeout())

def open_handshake_socket(host: String, port: U32) -> IO(Result<&1,&1,U32 & String,Socket>):
  import "./quic_datagram.c"

# Read at most one datagram on this socket. Zero means pending, one means the
# pinned handshake completed on this route.
def read_handshake_socket(conn: DatagramConnection, socket: Socket)
    -> IO(DatagramConnection & (Socket & Result<&1,&1,U32 & String,U32>)):
  import "./quic_datagram.c"

# Advance the QUIC timer and return the next outbound datagram, or [].
def route_handshake_output(conn: DatagramConnection)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,List<&2,U32>>):
  import "./quic_datagram.c"

def adopt_handshake_socket(conn: DatagramConnection, socket: Socket)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_datagram.c"

# Process UDP input, timer expiry, and one outgoing packet.
# The result is 1 once the peer key and QUIC handshake are verified.
def step_quic_datagram(conn: DatagramConnection)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

# Validate a new numeric local address for a direct dial. Port 0 chooses a
# free UDP port. The result is the bound port or 0 to retry after stepping.
def start_quic_migration(conn: DatagramConnection, host: String, port: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

# Validate a new local and remote address for the existing pinned peer.
# An empty local host with port zero lets the OS select a source address.
def start_quic_path_migration(conn: DatagramConnection, host: String, port: U32, peer: String, peer_port: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

# 0 means idle, 1 validating, 2 migrated, and 3 validation failed.
def quic_migration_status(conn: DatagramConnection)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

# Set a keepalive interval in milliseconds and start monitoring authenticated input.
# Pass zero to disable path monitoring and keepalives.
def monitor_quic_path(conn: DatagramConnection, interval: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_datagram.c"

# Return time since authenticated input and the current probe timeout in milliseconds.
def quic_path_timing(conn: DatagramConnection)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32 & U32>):
  import "./quic_datagram.c"

def quic_millis() -> IO(U32):
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
def connect_with_idle_timeout(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, timeout_ms: Nat, idle_ms: NatWire.VarInt) -> IO(Result<&1,&1,U32 & String,DatagramConnection>):
  do IO<Result<&1,&1,U32 & String,DatagramConnection>>:
    started : Result<&1,&1,U32 & String,DatagramConnection> <-
      start_quic_datagram_with_idle_timeout(host,port,secret,peer,alpn,idle_ms)
    begin_handshake(started,timeout_ms)

def connect(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, timeout_ms: Nat) -> IO(Result<&1,&1,U32 & String,DatagramConnection>):
  connect_with_idle_timeout(host,port,secret,peer,alpn,timeout_ms,Close.default_idle_timeout())

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
# End one stream half and keep the opposite half available.
def cancel_quic_stream_half(conn: DatagramConnection, stream: U32, half: U32, high: U32, low: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_datagram.c"

def reset_quic_stream(conn: DatagramConnection, stream: U32, code: NatWire.VarInt)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,Unit>):
  NatWire.Var{high,low} = code
  cancel_quic_stream_half(conn,stream,0,high,low)

def stop_quic_stream(conn: DatagramConnection, stream: U32, code: NatWire.VarInt)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,Unit>):
  NatWire.Var{high,low} = code
  cancel_quic_stream_half(conn,stream,1,high,low)

def peer_quic_stream_code(conn: DatagramConnection, stream: U32, half: U32) -> IO(Stream.CodeWords(DatagramConnection)):
  import "./quic_datagram.c"

# None until the peer sends RESET_STREAM on the receive half or
# STOP_SENDING on the send half. A peer code of zero returns Some.
def quic_stream_reset_code(conn: DatagramConnection, stream: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,Maybe<&2,NatWire.VarInt>>):
  do IO<Stream.CodeResult(DatagramConnection)>:
    raw : Stream.CodeWords(DatagramConnection) <- peer_quic_stream_code(conn,stream,1)
    Stream.peer_code(DatagramConnection,raw)

def quic_stream_stop_code(conn: DatagramConnection, stream: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,Maybe<&2,NatWire.VarInt>>):
  do IO<Stream.CodeResult(DatagramConnection)>:
    raw : Stream.CodeWords(DatagramConnection) <- peer_quic_stream_code(conn,stream,0)
    Stream.peer_code(DatagramConnection,raw)

# One after the peer has acknowledged every byte and FIN. Zero while pending.
def quic_stream_fin_acked(conn: DatagramConnection, stream: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

def quic_stream_reset_acked(conn: DatagramConnection, stream: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

def drop_quic_stream(conn: DatagramConnection, stream: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_datagram.c"

type QuicDatagramListener is Type:
  QuicDatagramListener{id: U32}

# Bind a concrete IPv4 or IPv6 address. Port zero picks an available port.
def bind_shared_quic_with_idle_timeout(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>,
    idle_ms: NatWire.VarInt) -> IO(Result<&1,&1,U32 & String,QuicDatagramListener & U32>):
  import "./quic_datagram.c"

def bind_shared_quic(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,QuicDatagramListener & U32>):
  bind_shared_quic_with_idle_timeout(host,port,secret,peer,alpn,Close.default_idle_timeout())

# Process listener traffic and return a connection after key and ALPN verification.
def try_accept_shared_quic(listener: QuicDatagramListener)
    -> IO(QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,DatagramConnection>>):
  import "./quic_datagram.c"

# Stop accepting connections. Existing connections keep their UDP socket.
def close_shared_quic(listener: QuicDatagramListener) -> IO(Unit):
  import "./quic_datagram.c"

type QuicSession is Type:
  QuicSession{id: U32}

# Ticket availability is driven by connection steps after handshake completion.
def take_quic_session(conn: DatagramConnection)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,QuicSession>>):
  import "./quic_datagram.c"

# Consumes a ticket. Its local key, peer key, and ALPN must match.
# Pass 1 to allow early data or 0 for handshake-only resumption.
def start_quic_resume(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, session: QuicSession, early: U32)
    -> IO(Result<&1,&1,U32 & String,DatagramConnection>):
  import "./quic_datagram.c"

def drop_quic_session(session: QuicSession) -> IO(Unit):
  import "./quic_datagram.c"

# Send only data the application can safely receive more than once.
# 1 means the stack accepted the datagram for transmission.
def write_early_datagram(conn: DatagramConnection, payload: List<&2,U32>)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

# After authentication the result is (TLS resumed, early-data status).
# Early-data status is 0 when unused, 1 when accepted, and 2 when rejected.
def quic_resumption_status(conn: DatagramConnection)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,Maybe<&1,U32 & U32>>):
  import "./quic_datagram.c"

# Opens a replayable stream before the handshake. Use the normal queue and
# flush calls. If early data is rejected, release the handle and open a new stream.
def open_early_quic_stream(conn: DatagramConnection, direction: U32)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_datagram.c"

# Opt in to TLS tickets and early data. Connections are handed to the
# application after authentication, including any buffered early data.
# Authenticate each connecting Ed25519 identity. Set early_data to 1 to issue 0-RTT tickets.
def bind_quic_identity(host: String, port: U32, secret: List<&2,U32>, alpn: List<&2,U32>, early_data: U32)
    -> IO(Result<&1,&1,U32 & String,QuicDatagramListener & U32>):
  import "./quic_datagram.c"

def bind_dual_quic_identity(host: String, port: U32, secret: List<&2,U32>, alpn: List<&2,U32>, early_data: U32)
    -> IO(Result<&1,&1,U32 & String,QuicDatagramListener & U32>):
  import "./quic_datagram.c"

def quic_remote_id(conn: DatagramConnection)
    -> IO(DatagramConnection & Result<&1,&1,U32 & String,List<&2,U32>>):
  import "./quic_datagram.c"

def bind_resumable_quic(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,QuicDatagramListener & U32>):
  import "./quic_datagram.c"

def send_quic_application_close(conn: DatagramConnection, high: U32, low: U32, reason: List<&2,U32>)
    -> IO(DatagramConnection & Close.WriteResult()):
  import "./quic_datagram.c"

def read_quic_application_close(conn: DatagramConnection) -> IO(DatagramConnection & Close.NativeResult()):
  import "./quic_datagram.c"

# Close immediately with a 62-bit application code and uninterpreted reason bytes.
def close_quic_connection(conn: DatagramConnection, code: NatWire.VarInt, reason: List<&2,U32>)
    -> IO(DatagramConnection & Close.WriteResult()):
  Close.close(DatagramConnection,conn,code,reason,send_quic_application_close)

def quic_close_packet(conn: DatagramConnection) -> IO(DatagramConnection & Result<&1,&1,U32 & String,List<&2,U32>>):
  import "./quic_datagram.c"

def quic_close_reason(conn: DatagramConnection) -> IO(DatagramConnection & Close.ReadResult()):
  do IO<DatagramConnection & Close.ReadResult()>:
    raw : DatagramConnection & Close.ReadResult() <- Close.observe(DatagramConnection,conn,read_quic_application_close)
    CloseWire.expand(DatagramConnection,raw,quic_close_packet)
