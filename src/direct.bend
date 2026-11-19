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
