import Base

type QuicListener is Type:
  BoundUdp{id: U32}

type QuicStream is Type:
  AcceptedStream{id: U32}

# Direct IPv4/IPv6 QUIC with mutually pinned Ed25519 endpoint keys and one
# bidirectional stream per connection. The native host uses OpenSSL.
def bind(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>) -> IO(Result<&1,&1,U32 & String, QuicListener & U32>):
  import "./direct.c"

# Consumes the listener. Read the request to FIN and return its stream.
def accept(listener: QuicListener, limit: U32) ->
    IO(Result<&1,&1,U32 & String, QuicStream & List<&2,U32>>):
  import "./direct.c"

# Consumes the stream, writes the response, and finishes the connection.
def respond(stream: QuicStream, response: List<&2,U32>) -> IO(Result<&1,&1,U32 & String, Unit>):
  import "./direct.c"

def close(listener: QuicListener) -> IO(Result<&1,&1,U32 & String, Unit>):
  import "./direct.c"

def abort(stream: QuicStream) -> IO(Result<&1,&1,U32 & String, Unit>):
  import "./direct.c"

def exchange(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>, request: List<&2,U32>, limit: U32) ->
    IO(Result<&1,&1,U32 & String, List<&2,U32>>):
  import "./direct.c"

type QuicConnection is Type:
  LiveConnection{id: U32}

type QuicIoStream is Type:
  LiveStream{id: U32}

# Establish a pinned connection without creating a default stream.
def quic_connect(host: String, port: U32, secret: List<&2,U32>, peer: List<&2,U32>,
    alpn: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,QuicConnection>):
  import "./direct.c"

# Accept one authenticated connection and transfer ownership of the listener.
def quic_accept_connection(listener: QuicListener) -> IO(Result<&1,&1,U32 & String,QuicConnection>):
  import "./direct.c"

# Poll for an authenticated connection while retaining the listener. Once
# polled, use this operation for subsequent accepts on that listener.
# Closing the listener stops new handshakes. Accepted connections keep their
# shared UDP socket until their own handles and stream handles are released.
def quic_try_accept_connection(listener: QuicListener)
    -> IO(QuicListener & Poll<&1,&1,Result<&1,&1,U32 & String,QuicConnection>,Unit>):
  import "./direct.c"

# A direction of 0 opens a bidirectional stream, and 1 opens a send-only
# stream. Poll results preserve the connection even on a stream error.
def quic_open_stream(conn: QuicConnection, direction: U32)
    -> IO(QuicConnection & Poll<&1,&1,Result<&1,&1,U32 & String,QuicIoStream>,Unit>):
  import "./direct.c"

# Readiness means an incoming stream is available. An incoming
# unidirectional stream can only be read.
def quic_accept_stream(conn: QuicConnection)
    -> IO(QuicConnection & Poll<&1,&1,Result<&1,&1,U32 & String,QuicIoStream>,Unit>):
  import "./direct.c"

# Read at most limit bytes. None means the peer finished its send half.
def quic_read(stream: QuicIoStream, limit: U32)
    -> IO(QuicIoStream & Poll<&1,&1,Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>,Unit>):
  import "./direct.c"

# Queue at most one MiB. Flush the queued write before queuing another.
def quic_queue_write(stream: QuicIoStream, data: List<&2,U32>)
    -> IO(QuicIoStream & Result<&1,&1,U32 & String,Unit>):
  import "./direct.c"

# Ready when the queued write has been accepted by the QUIC stack.
def quic_flush(stream: QuicIoStream)
    -> IO(QuicIoStream & Poll<&1,&1,Result<&1,&1,U32 & String,Unit>,Unit>):
  import "./direct.c"

# Send FIN after flushing the queued write. The receive half stays open.
def quic_finish(stream: QuicIoStream) -> IO(QuicIoStream & Result<&1,&1,U32 & String,Unit>):
  import "./direct.c"

def quic_drop_stream(stream: QuicIoStream) -> IO(Unit):
  import "./direct.c"

# Drive the connection when the application has no active stream operation.
def quic_tick(conn: QuicConnection) -> IO(QuicConnection & Result<&1,&1,U32 & String,Unit>):
  import "./direct.c"

def quic_shutdown(conn: QuicConnection)
    -> IO(QuicConnection & Poll<&1,&1,Result<&1,&1,U32 & String,Unit>,Unit>):
  import "./direct.c"

def quic_drop_connection(conn: QuicConnection) -> IO(Unit):
  import "./direct.c"
