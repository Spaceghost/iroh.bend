import Base
import ./quic_stream.bend as Stream
import ./quic_close.bend as Close
import ./quic_nat.bend as NatWire

type MultipathConnection is Type:
  MultipathConnection{id: U32}

type MultipathListener is Type:
  MultipathListener{id: U32}

type MultipathSession is Type:
  MultipathSession{id: U32}

type MultipathEarlyStream is Type:
  MultipathEarlyStream{id: U32}

type MultipathRead is Data:
  MultipathReadPending{}
  MultipathReadFin{}
  MultipathReadBytes{bytes: List<&2,U32>}

# Bend owns every candidate socket until the pinned TLS handshake selects one.
def start_multipath_route_handshake_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: List<&2,U32>,
    idle_ms: NatWire.VarInt) -> IO(Result<&1,&1,U32 & String,MultipathConnection & Socket>):
  import "./quic_multipath.c"

def start_multipath_route_handshake(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,MultipathConnection & Socket>):
  start_multipath_route_handshake_with_idle_timeout(host,port,seed,peer,alpn,Close.default_idle_timeout())

def start_multipath_nat_route_handshake_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, parameter: List<&2,U32>, idle_ms: NatWire.VarInt)
    -> IO(Result<&1,&1,U32 & String,MultipathConnection & Socket>):
  import "./quic_multipath.c"

def start_multipath_nat_route_handshake(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, parameter: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,MultipathConnection & Socket>):
  start_multipath_nat_route_handshake_with_idle_timeout(host,port,seed,peer,alpn,parameter,Close.default_idle_timeout())

def open_multipath_handshake_socket(host: String, port: U32) -> IO(Result<&1,&1,U32 & String,Socket>):
  import "./quic_multipath.c"

def read_multipath_handshake_socket(conn: MultipathConnection, socket: Socket)
    -> IO(MultipathConnection & (Socket & Result<&1,&1,U32 & String,U32>)):
  import "./quic_multipath.c"

def multipath_handshake_output(conn: MultipathConnection) -> IO(MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>>):
  import "./quic_multipath.c"

def adopt_multipath_handshake_socket(conn: MultipathConnection, socket: Socket)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

def start_multipath(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: String)
    -> IO(Result<&1,&1,U32 & String,MultipathConnection>):
  import "./quic_multipath.c"

# TLS protocol identifiers are 1 to 255 opaque bytes.
def start_multipath_nat_offer_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: String,
    parameter: List<&2,U32>, idle_ms: NatWire.VarInt) -> IO(Result<&1,&1,U32 & String,MultipathConnection>):
  import "./quic_multipath.c"

def start_multipath_nat_offer(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: String,
    parameter: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,MultipathConnection>):
  start_multipath_nat_offer_with_idle_timeout(host,port,seed,peer,alpn,parameter,Close.default_idle_timeout())

def start_nat_parameter(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: String,
    parameter: Maybe<&2,List<&2,U32>>, idle_ms: NatWire.VarInt) -> IO(Result<&1,&1,U32 & String,MultipathConnection>):
  match parameter:
    case Some{encoded}:
      start_multipath_nat_offer_with_idle_timeout(host,port,seed,peer,alpn,encoded,idle_ms)
    case None{}:
      IO.pure(Result<&1,&1,U32 & String,MultipathConnection>,Fail{(22,"invalid NAT traversal limit")})

def start_multipath_with_nat_limit_and_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: String,
    limit: U32, idle_ms: NatWire.VarInt) -> IO(Result<&1,&1,U32 & String,MultipathConnection>):
  start_nat_parameter(host,port,seed,peer,alpn,NatWire.encode_limit(limit),idle_ms)

def start_multipath_with_nat_limit(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: String,
    limit: U32) -> IO(Result<&1,&1,U32 & String,MultipathConnection>):
  start_multipath_with_nat_limit_and_idle_timeout(host,port,seed,peer,alpn,limit,Close.default_idle_timeout())

def start_multipath_bytes_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: List<&2,U32>,
    idle_ms: NatWire.VarInt) -> IO(Result<&1,&1,U32 & String,MultipathConnection>):
  import "./quic_multipath.c"

def start_multipath_bytes(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,MultipathConnection>):
  start_multipath_bytes_with_idle_timeout(host,port,seed,peer,alpn,Close.default_idle_timeout())

def start_multipath_alpns(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>) -> IO(Result<&1,&1,U32 & String,MultipathConnection>):
  import "./quic_multipath.c"

# Return the exact protocol bytes once the connection is ready.
def negotiated_multipath_alpn(conn: MultipathConnection)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>>):
  import "./quic_multipath.c"

# Return the TLS-authenticated transport parameters from a connected peer.
def peer_multipath_parameters(conn: MultipathConnection)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>>):
  import "./quic_multipath.c"

# Dequeue a role-appropriate NAT traversal wire frame from an opted-in connection.
def read_multipath_nat_frame(conn: MultipathConnection)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>):
  import "./quic_multipath.c"

# A 9-byte PATH_CHALLENGE with a fresh random token. Returns 1 when queued.
def send_multipath_nat_challenge(conn: MultipathConnection, ip: List<&2,U32>, port: U32, challenge: List<&2,U32>)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

# Returns 1 once for the matching authenticated response from this address.
def take_multipath_nat_response(conn: MultipathConnection, ip: List<&2,U32>, port: U32, challenge: List<&2,U32>)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

# Send one role-appropriate NAT control frame at a time. Step QUIC and
# call again with the same frame until the peer acknowledges it.
def send_multipath_nat_address(conn: MultipathConnection, frame: List<&2,U32>)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

# Return the numeric IP bytes and port of the socket used for NAT probes.
# Bind an independent UDP source for an opted-in dial through a relay bridge.
def bind_multipath_nat_source(conn: MultipathConnection, host: String, port: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

# Find or bind the UDP source for this peer candidate's address family.
def route_multipath_nat_source(conn: MultipathConnection, address: List<&2,U32>, port: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32> & U32>):
  import "./quic_multipath.c"

# Query the relay's /iroh-qad/0 service on the same UDP socket used for probes.
def start_multipath_qad(conn: MultipathConnection, ip: String, port: U32, tls_name: String, roots: String)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

def poll_multipath_qad(conn: MultipathConnection)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32> & U32>>):
  import "./quic_multipath.c"

# Resolve the relay once for best-effort address discovery on routed sockets.
def configure_routed_qad(conn: MultipathConnection, host: String, port: U32) -> IO(MultipathConnection):
  import "./quic_multipath.c"

def QadSocket() -> Type:
  List<&2,U32> & U32

def QadChange() -> Type:
  Maybe<&1,QadSocket()> & QadSocket()

def poll_routed_qad(conn: MultipathConnection)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,QadChange()>>):
  import "./quic_multipath.c"

# Resolve the QAD service for the two shared listener sockets.
def configure_listener_qad(listener: MultipathListener, host: String, port: U32) -> IO(MultipathListener):
  import "./quic_multipath.c"

def QadSnapshot() -> Type:
  U32 & (Maybe<&1,QadSocket()> & Maybe<&1,QadSocket()>)

def listener_qad_addresses(conn: MultipathConnection, revision: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,QadSnapshot()>>):
  import "./quic_multipath.c"

def multipath_nat_local_candidate(conn: MultipathConnection)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32> & U32>):
  import "./quic_multipath.c"

# After a matching NAT probe response, open a new QUIC path using the
# punched socket. Wait for the returned path ID to become available.
def open_multipath_nat_path(conn: MultipathConnection, ip: List<&2,U32>, port: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>):
  import "./quic_multipath.c"

type IdleDuration is Data:
  IdleMicros{high: U32, low: U32}

def PathIdleSample() -> Type:
  U32 & (IdleDuration & (IdleDuration & IdleDuration))

def PathTimers() -> Type:
  List<&1,PathIdleSample()> & List<&1,U32 & U32>

def relay_path_idle_timeout() -> U32:
  30000

def read_multipath_step(conn: MultipathConnection, direct_idle_ms: U32, relay_idle_ms: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,PathTimers()>):
  import "./quic_multipath.c"

def write_multipath_step(conn: MultipathConnection, expired: List<&1,U32>, reason: U32, heartbeats: List<&1,U32>)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

def idle_time_ge(a: IdleDuration, b: IdleDuration) -> Bool:
  IdleMicros{+a_high,a_low} = a
  IdleMicros{+b_high,b_low} = b
  U32.is_gt(a_high,b_high) || (U32.is_eq(a_high,b_high) && U32.is_ge(a_low,b_low))

def reached_pto_floor(age: IdleDuration, pto: IdleDuration) -> Bool:
  IdleMicros{+high,+low} = pto
  # Multiply in 16-bit pieces to carry the low word into the high word.
  +bottom = U32.mul(U32.and(low,65535),3)
  +top = U32.add(U32.mul(U32.shrn(low,16n),3),U32.shrn(bottom,16n))
  +carry = U32.shrn(top,16n)
  (U32.is_lt(high,1431655765) || (U32.is_eq(high,1431655765) && U32.is_zero(carry))) &&
    idle_time_ge(age,IdleMicros{U32.add(U32.mul(high,3),carry),U32.or(U32.shln(top,16n),U32.and(bottom,65535))})

def add_due_path(path: U32, rest: List<&1,U32>, due: Bool) -> List<&1,U32>:
  match due:
    case True{}:
      Con{path,rest}
    case False{}:
      rest

def expired_multipath_samples(samples: List<&1,PathIdleSample()>) -> List<&1,U32>:
  match samples:
    case Nil{}:
      []
    case Con{(path,(limit,(+age,pto))),rest}:
      add_due_path(path,expired_multipath_samples(rest),idle_time_ge(age,limit) && reached_pto_floor(age,pto))

def multipath_heartbeats(samples: List<&1,U32 & U32>) -> List<&1,U32>:
  match samples:
    case Nil{}:
      []
    case Con{(path,age_ms),rest}:
      add_due_path(path,multipath_heartbeats(rest),U32.is_ge(age_ms,5000))

def finish_multipath_step(progress: MultipathConnection & Result<&1,&1,U32 & String,PathTimers()>)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  match progress:
    case (conn,Done{(idle,activity)}):
      # PATH_UNSTABLE_OR_POOR is the Iroh wire code for local path expiry.
      write_multipath_step(conn,expired_multipath_samples(idle),15990,multipath_heartbeats(activity))
    case (conn,Fail{error}):
      IO.pure(MultipathConnection & Result<&1,&1,U32 & String,U32>,(conn,Fail{error}))

# Drive pending network and timer work. 0 means handshaking, 1 means ready
# with base QUIC, and 2 means the peer negotiated multipath.
def step_multipath(conn: MultipathConnection) -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  do IO<MultipathConnection & Result<&1,&1,U32 & String,U32>>:
    progress : MultipathConnection & Result<&1,&1,U32 & String,PathTimers()> <-
      read_multipath_step(conn,15000,relay_path_idle_timeout())
    finish_multipath_step(progress)

# Override one path's local timer and rearm it. Zero disables the path timer.
def set_multipath_path_idle_timeout(conn: MultipathConnection, path: U32, idle_ms: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

# The endpoint marks the path selected through its local relay bridge.
def mark_multipath_relay_path(conn: MultipathConnection, path: U32) -> IO(MultipathConnection):
  import "./quic_multipath.c"

# Step the authenticated client connection until its peer sends a ticket.
# A returned session owns the ticket independently of the connection.
def take_multipath_session(conn: MultipathConnection)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,MultipathSession>>):
  import "./quic_multipath.c"

def drop_multipath_session(session: MultipathSession) -> IO(Unit):
  import "./quic_multipath.c"

# Pass one to enable 0-RTT. The new connection advertises idle_ms even on full TLS fallback.
def start_multipath_resume_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, session: MultipathSession, early_data: U32, idle_ms: NatWire.VarInt)
    -> IO(Result<&1,&1,U32 & String,MultipathConnection>):
  import "./quic_multipath.c"

# Consume a session for the same local identity, peer key, and ALPN bytes.
# If the peer rejects it, Picoquic attempts the pinned full handshake.
def start_multipath_resume(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, session: MultipathSession) -> IO(Result<&1,&1,U32 & String,MultipathConnection>):
  start_multipath_resume_with_idle_timeout(host,port,seed,peer,alpn,session,0,Close.default_idle_timeout())

# Opt in to sending replay-safe application data before the handshake completes.
def start_multipath_early(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, session: MultipathSession) -> IO(Result<&1,&1,U32 & String,MultipathConnection>):
  start_multipath_resume_with_idle_timeout(host,port,seed,peer,alpn,session,1,Close.default_idle_timeout())

# None while handshaking. After authentication, 1 means TLS accepted early data.
def multipath_early_status(conn: MultipathConnection)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>):
  import "./quic_multipath.c"

# None while handshaking. After authentication, 1 means TLS resumed.
def multipath_resumption_status(conn: MultipathConnection)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>):
  import "./quic_multipath.c"

# An empty bind host lets the OS select the local address and port.
# For an explicit bind address, port zero chooses a free port.
# None means retry after stepping.
# A returned path ID can be used after its state becomes available.
def probe_multipath(conn: MultipathConnection, bind_host: String, bind_port: U32, peer: String, peer_port: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>):
  import "./quic_multipath.c"

# Path 0 is the initial path. States are 0 probing, 1 available,
# 2 suspended, and 3 retired.
def multipath_status(conn: MultipathConnection, path: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

# Count consecutive timeout retransmissions on a path since its last ACK.
def multipath_path_timeouts(conn: MultipathConnection, path: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

# Send QUIC keepalives at this interval in milliseconds. Zero disables them.
def set_multipath_keepalive(conn: MultipathConnection, interval: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

# Try a second address on the same unvalidated path without consuming a path ID.
def probe_multipath_alternate(conn: MultipathConnection, path: U32, peer: String, port: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

# Make a path a standby for regular traffic, or restore it with standby zero.
def set_multipath_standby(conn: MultipathConnection, path: U32, standby: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

def retire_multipath_path(conn: MultipathConnection, path: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

def multipath_millis() -> IO(U32):
  import "./quic_multipath.c"

def multipath_micros() -> IO(U32):
  import "./quic_multipath.c"

# Find the next available path after the given ID, including paths opened by the peer.
def next_multipath_path(conn: MultipathConnection, after: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>):
  import "./quic_multipath.c"

# Largest payload the peer and all current paths can carry. Zero before negotiation.
def multipath_datagram_limit(conn: MultipathConnection)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

# 1 means queued. 0 means retry after stepping. QUIC never retransmits datagrams.
def write_multipath_datagram(conn: MultipathConnection, bytes: List<&2,U32>)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

def write_multipath_early_frame(conn: MultipathConnection, frame: List<&2,U32>)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

def early_datagram_frame(+size: U32, bytes: List<&2,U32>, short: Bool) -> List<&2,U32>:
  match short:
    case True{}:
      Con{49,Con{size,bytes}}
    case False{}:
      Con{49,Con{U32.or(64,U32.shrn(size,8n)),Con{U32.and(size,255),bytes}}}

def checked_early_datagram(conn: MultipathConnection, bytes: List<&2,U32>, length: Nat, fits: Bool)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  match fits:
    case True{}:
      +size = U32.from_nat(length)
      write_multipath_early_frame(conn,early_datagram_frame(size,bytes,U32.is_lt(size,64)))
    case False{}:
      IO.pure(MultipathConnection & Result<&1,&1,U32 & String,U32>,
        (conn,Fail{(1,"early QUIC datagram exceeds packet capacity")}))

# Call immediately after start_multipath_early, before stepping the connection.
# 1 means packetized. 0 means no packet included this datagram.
# QUIC datagrams can be lost and rejected early datagrams are never retried.
def write_multipath_early_datagram(conn: MultipathConnection, +bytes: List<&2,U32>)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  +length = List.length(&2,U32,bytes)
  checked_early_datagram(conn,bytes,length,Nat.is_lt(length,16384n))

# An empty received datagram is Some{[]}.
def read_multipath_datagram(conn: MultipathConnection)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>):
  import "./quic_multipath.c"

# Direction zero is bidirectional. Direction one is send-only.
def open_multipath_stream(conn: MultipathConnection, direction: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>):
  import "./quic_multipath.c"

# Open and queue replay-safe bytes before stepping the resumed connection.
def open_multipath_early_stream(conn: MultipathConnection, direction: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,MultipathEarlyStream>>):
  import "./quic_multipath.c"

def write_multipath_early_stream(conn: MultipathConnection, stream: MultipathEarlyStream, bytes: List<&2,U32>, fin: U32)
    -> IO(MultipathConnection & (MultipathEarlyStream & Result<&1,&1,U32 & String,U32>)):
  import "./quic_multipath.c"

# Call after authentication. A rejected stream returns None and its bytes
# are discarded. An accepted stream ID can be used with the regular API.
def resolve_multipath_early_stream(conn: MultipathConnection, stream: MultipathEarlyStream)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>):
  import "./quic_multipath.c"

# Poll for a peer-initiated bidirectional or receive-only stream.
def accept_multipath_stream(conn: MultipathConnection, direction: U32)
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

# End one stream half and keep the opposite half available.
def cancel_multipath_stream_half(conn: MultipathConnection, stream: U32, half: U32, high: U32, low: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

def reset_multipath_stream(conn: MultipathConnection, stream: U32, code: NatWire.VarInt)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  NatWire.Var{high,low} = code
  cancel_multipath_stream_half(conn,stream,0,high,low)

def stop_multipath_stream(conn: MultipathConnection, stream: U32, code: NatWire.VarInt)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  NatWire.Var{high,low} = code
  cancel_multipath_stream_half(conn,stream,1,high,low)

def peer_multipath_stream_code(conn: MultipathConnection, stream: U32, half: U32) -> IO(Stream.CodeWords(MultipathConnection)):
  import "./quic_multipath.c"

# None until the peer sends RESET_STREAM on the receive half or
# STOP_SENDING on the send half. A peer code of zero returns Some.
def multipath_stream_reset_code(conn: MultipathConnection, stream: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&2,NatWire.VarInt>>):
  do IO<Stream.CodeResult(MultipathConnection)>:
    raw : Stream.CodeWords(MultipathConnection) <- peer_multipath_stream_code(conn,stream,1)
    Stream.peer_code(MultipathConnection,raw)

def multipath_stream_stop_code(conn: MultipathConnection, stream: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Maybe<&2,NatWire.VarInt>>):
  do IO<Stream.CodeResult(MultipathConnection)>:
    raw : Stream.CodeWords(MultipathConnection) <- peer_multipath_stream_code(conn,stream,0)
    Stream.peer_code(MultipathConnection,raw)

# One after the peer has acknowledged every byte and FIN. Zero while pending.
def multipath_stream_fin_acked(conn: MultipathConnection, stream: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  multipath_stream_close_acked(conn,stream,0)

def multipath_stream_reset_acked(conn: MultipathConnection, stream: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  multipath_stream_close_acked(conn,stream,1)

def multipath_stream_close_acked(conn: MultipathConnection, stream: U32, reset: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

def drop_multipath_stream(conn: MultipathConnection, stream: U32)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

def close_multipath(conn: MultipathConnection) -> IO(Unit):
  import "./quic_multipath.c"

def bind_multipath(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: String)
    -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  import "./quic_multipath.c"

# Low-level transport fixture. The normal listener waits for QNT frame handling.
def bind_multipath_nat_offer_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: String,
    parameter: List<&2,U32>, idle_ms: NatWire.VarInt) -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  import "./quic_multipath.c"

def bind_multipath_nat_offer(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: String,
    parameter: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  bind_multipath_nat_offer_with_idle_timeout(host,port,seed,peer,alpn,parameter,Close.default_idle_timeout())

def bind_nat_parameter(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: String,
    parameter: Maybe<&2,List<&2,U32>>, idle_ms: NatWire.VarInt) -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  match parameter:
    case Some{encoded}:
      bind_multipath_nat_offer_with_idle_timeout(host,port,seed,peer,alpn,encoded,idle_ms)
    case None{}:
      IO.pure(Result<&1,&1,U32 & String,MultipathListener & U32>,Fail{(22,"invalid NAT traversal limit")})

def bind_multipath_with_nat_limit_and_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: String,
    limit: U32, idle_ms: NatWire.VarInt) -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  bind_nat_parameter(host,port,seed,peer,alpn,NatWire.encode_limit(limit),idle_ms)

def bind_multipath_with_nat_limit(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: String,
    limit: U32) -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  bind_multipath_with_nat_limit_and_idle_timeout(host,port,seed,peer,alpn,limit,Close.default_idle_timeout())

def bind_multipath_bytes_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: List<&2,U32>,
    idle_ms: NatWire.VarInt) -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  import "./quic_multipath.c"

def bind_multipath_bytes(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  bind_multipath_bytes_with_idle_timeout(host,port,seed,peer,alpn,Close.default_idle_timeout())

# Accept tickets and 0-RTT from this peer. Application I/O starts after authentication.
def bind_resumable_multipath_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: List<&2,U32>,
    idle_ms: NatWire.VarInt)
    -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  import "./quic_multipath.c"

def bind_resumable_multipath(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  bind_resumable_multipath_with_idle_timeout(host,port,seed,peer,alpn,Close.default_idle_timeout())

# Authenticate each connecting Ed25519 peer. List ALPNs in server preference order.
def bind_multipath_identity_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>, early_data: U32,
    idle_ms: NatWire.VarInt)
    -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  import "./quic_multipath.c"

def bind_multipath_identity(host: String, port: U32, seed: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>, early_data: U32)
    -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  bind_multipath_identity_with_idle_timeout(host,port,seed,alpns,early_data,Close.default_idle_timeout())

def bind_dual_multipath_identity_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>, early_data: U32,
    idle_ms: NatWire.VarInt)
    -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  import "./quic_multipath.c"

def bind_dual_multipath_identity(host: String, port: U32, seed: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>, early_data: U32)
    -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  bind_dual_multipath_identity_with_idle_timeout(host,port,seed,alpns,early_data,Close.default_idle_timeout())

def bind_dual_multipath_nat_identity_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>, early_data: U32, parameter: List<&2,U32>, idle_ms: NatWire.VarInt)
    -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  import "./quic_multipath.c"

def bind_dual_multipath_nat_identity(host: String, port: U32, seed: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>, early_data: U32, parameter: List<&2,U32>)
    -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  bind_dual_multipath_nat_identity_with_idle_timeout(host,port,seed,alpns,early_data,parameter,Close.default_idle_timeout())

def multipath_remote_id(conn: MultipathConnection)
    -> IO(MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>>):
  import "./quic_multipath.c"

# List protocols in server preference order.
def bind_multipath_alpns(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>) -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  import "./quic_multipath.c"

def bind_multipath_alpns_nat_offer_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>, parameter: List<&2,U32>, idle_ms: NatWire.VarInt)
    -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  import "./quic_multipath.c"

def bind_multipath_alpns_nat_offer(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>, parameter: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,MultipathListener & U32>):
  bind_multipath_alpns_nat_offer_with_idle_timeout(host,port,seed,peer,alpns,parameter,Close.default_idle_timeout())

# Replace the preference list for new handshakes. An empty list pauses admission.
def set_multipath_alpns(listener: MultipathListener, alpns: List<&2,List<&2,U32>>)
    -> IO(MultipathListener & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

# Feed the relay bridge into a private loopback socket on the same QUIC listener.
def bind_multipath_relay_socket(listener: MultipathListener)
    -> IO(MultipathListener & Result<&1,&1,U32 & String,U32>):
  import "./quic_multipath.c"

# Drive the listener and poll for an authenticated connection.
def accept_multipath(listener: MultipathListener)
    -> IO(MultipathListener & Result<&1,&1,U32 & String,Maybe<&1,MultipathConnection>>):
  import "./quic_multipath.c"

# Stop accepting new connections. Accepted connections keep their UDP socket.
def close_multipath_listener(listener: MultipathListener) -> IO(Unit):
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

def connect_multipath_with_nat_limit_and_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: String, limit: U32, timeout_ms: Nat, idle_ms: NatWire.VarInt) -> IO(ConnectResult()):
  do IO<ConnectResult()>:
    started : ConnectResult() <- start_multipath_with_nat_limit_and_idle_timeout(host,port,seed,peer,alpn,limit,idle_ms)
    finish_connect(started,timeout_ms)

def connect_multipath_with_nat_limit(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: String, limit: U32, timeout_ms: Nat) -> IO(ConnectResult()):
  connect_multipath_with_nat_limit_and_idle_timeout(host,port,seed,peer,alpn,limit,timeout_ms,Close.default_idle_timeout())

def start_multipath_nat_offer_bytes_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, parameter: List<&2,U32>, idle_ms: NatWire.VarInt) -> IO(ConnectResult()):
  import "./quic_multipath.c"

def start_multipath_nat_offer_bytes(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, parameter: List<&2,U32>) -> IO(ConnectResult()):
  start_multipath_nat_offer_bytes_with_idle_timeout(host,port,seed,peer,alpn,parameter,Close.default_idle_timeout())

def connect_nat_bytes(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, encoded: Maybe<&2,List<&2,U32>>, timeout: Nat, idle_ms: NatWire.VarInt) -> IO(ConnectResult()):
  match encoded:
    case Some{parameter}:
      do IO<ConnectResult()>:
        started : ConnectResult() <- start_multipath_nat_offer_bytes_with_idle_timeout(host,port,seed,peer,alpn,parameter,idle_ms)
        finish_connect(started,timeout)
    case None{}:
      IO.pure(ConnectResult(),Fail{(22,"invalid NAT traversal limit")})

def connect_multipath_bytes_with_nat_limit_and_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, limit: U32, timeout: Nat, idle_ms: NatWire.VarInt) -> IO(ConnectResult()):
  connect_nat_bytes(host,port,seed,peer,alpn,NatWire.encode_limit(limit),timeout,idle_ms)

def connect_multipath_bytes_with_nat_limit(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, limit: U32, timeout: Nat) -> IO(ConnectResult()):
  connect_multipath_bytes_with_nat_limit_and_idle_timeout(host,port,seed,peer,alpn,limit,timeout,Close.default_idle_timeout())

def connect_multipath_bytes_with_idle_timeout(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, timeout_ms: Nat, idle_ms: NatWire.VarInt) -> IO(ConnectResult()):
  do IO<ConnectResult()>:
    started : ConnectResult() <- start_multipath_bytes_with_idle_timeout(host,port,seed,peer,alpn,idle_ms)
    finish_connect(started,timeout_ms)

def connect_multipath_bytes(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, timeout_ms: Nat) -> IO(ConnectResult()):
  connect_multipath_bytes_with_idle_timeout(host,port,seed,peer,alpn,timeout_ms,Close.default_idle_timeout())

def connect_multipath_alpns(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>, timeout_ms: Nat) -> IO(ConnectResult()):
  do IO<ConnectResult()>:
    started : ConnectResult() <- start_multipath_alpns(host,port,seed,peer,alpns)
    finish_connect(started,timeout_ms)


type QadServer is Type:
  QadServer{id: U32}

# Serve /iroh-qad/0 on a UDP address using a PEM certificate chain and key.
# Run this service alongside a WS or WSS relay.
def bind_qad_server(host: String, port: U32, certificate: String, key: String)
    -> IO(Result<&1,&1,U32 & String,QadServer & U32>):
  import "./quic_multipath.c"

# Pump one UDP packet and let QUIC report the observed client address.
def step_qad_server(server: QadServer) -> IO(QadServer & Result<&1,&1,U32 & String,Unit>):
  import "./quic_multipath.c"

def close_qad_server(server: QadServer) -> IO(Unit):
  import "./quic_multipath.c"

def send_multipath_application_close(conn: MultipathConnection, high: U32, low: U32, reason: List<&2,U32>)
    -> IO(MultipathConnection & Close.WriteResult()):
  import "./quic_multipath.c"

def read_multipath_application_close(conn: MultipathConnection) -> IO(MultipathConnection & Close.NativeResult()):
  import "./quic_multipath.c"

def close_multipath_connection(conn: MultipathConnection, code: NatWire.VarInt, reason: List<&2,U32>)
    -> IO(MultipathConnection & Close.WriteResult()):
  Close.close(MultipathConnection,conn,code,reason,send_multipath_application_close)

def multipath_close_reason(conn: MultipathConnection) -> IO(MultipathConnection & Close.ReadResult()):
  Close.observe(MultipathConnection,conn,read_multipath_application_close)
