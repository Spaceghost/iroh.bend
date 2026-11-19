import Base
import ../src/direct.bend as Direct

def payload() -> List<&2,U32>:
  [117,112,115,116,114,101,97,109,32,73,114,111,104,0,66,101,110,100,255,81,85,73,67]

def alpn() -> List<&2,U32>:
  [105,114,111,104,45,98,101,110,100,47,99,111,109,112,97,116,47,49]

def listener_public() -> List<&2,U32>:
  [25,127,107,35,225,108,133,50,198,171,200,56,250,205,94,167,
   137,190,12,118,178,146,3,52,3,155,250,139,61,54,141,97]

def dialer_public() -> List<&2,U32>:
  [119,44,138,68,43,125,176,110,22,108,251,193,204,188,188,222,
   111,62,186,118,164,233,142,243,255,197,25,80,34,55,214,239]

def equal(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(x, y) && equal(xs, ys)
    case _ _:
      False{}

def assert_equal(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.pure(Unit, Unit{})
    case False{}:
      IO.die(Unit, 1, "QUIC echo payload mismatch")

def echo(accepted: Direct.QuicStream & List<&2,U32>) -> IO(Unit):
  (stream, +bytes) = accepted
  do IO<Unit>:
    IO.try(Unit, Direct.respond(stream, bytes))
    assert_equal(equal(bytes, payload()))

def discard(accepted: Direct.QuicStream & List<&2,U32>) -> IO(Unit):
  (stream, _) = accepted
  IO.try(Unit, Direct.abort(stream))

def complete(accepted: Direct.QuicStream & List<&2,U32>, abort_reply: Bool) -> IO(Unit):
  match abort_reply:
    case True{}:
      discard(accepted)
    case False{}:
      echo(accepted)

def server(bound: Direct.QuicListener & U32, +abort_reply: Bool) -> IO(Unit):
  (listener, port) = bound
  do IO<Unit>:
    IO.print(String.append("127.0.0.1:", U32.show(port)))
    accepted : Direct.QuicStream & List<&2,U32> <- IO.try(Direct.QuicStream & List<&2,U32>, Direct.accept(listener, 1024))
    complete(accepted, abort_reply)

def listen(+abort_reply: Bool) -> IO(Unit):
  do IO<Unit>:
    bound : Direct.QuicListener & U32 <- IO.try(Direct.QuicListener & U32,
      Direct.bind("127.0.0.1", 0, List.replicate(U32, 32n, 42), dialer_public(), alpn()))
    server(bound, abort_reply)

def close_bound(bound: Direct.QuicListener & U32) -> IO(Unit):
  (listener, _) = bound
  IO.try(Unit, Direct.close(listener))

def check_close() -> IO(Unit):
  do IO<Unit>:
    bound : Direct.QuicListener & U32 <- IO.try(Direct.QuicListener & U32,
      Direct.bind("127.0.0.1", 0, List.replicate(U32, 32n, 42), dialer_public(), alpn()))
    close_bound(bound)

def dial(port: Maybe<&2,U32>, peer: List<&2,U32>) -> IO(Unit):
  match port:
    case Some{n}:
      do IO<Unit>:
        response : List<&2,U32> <- IO.try(List<&2,U32>,
          Direct.exchange("127.0.0.1", n, List.replicate(U32, 32n, 73), peer, alpn(), payload(), 1024))
        assert_equal(equal(response, payload()))
    case None{}:
      IO.die(Unit, 2, "expected a port")

def choose_listener(regular: Bool, aborting: Bool, closing: Bool) -> IO(Unit):
  match regular aborting closing:
    case True{} _ _:
      listen(False{})
    case _ True{} _:
      listen(True{})
    case _ _ True{}:
      check_close()
    case _ _ _:
      IO.die(Unit, 2, "expected listen, abort-listen or close")

def choose_peer(good: Bool, mismatch: Bool, port: String) -> IO(Unit):
  match good mismatch:
    case True{} _:
      dial(U32.read(port), listener_public())
    case False{} True{}:
      dial(U32.read(port), dialer_public())
    case False{} False{}:
      IO.die(Unit, 2, "expected dial or dial-wrong-key")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{+mode,Nil{}}}:
      choose_listener(String.eq(mode, "listen"), String.eq(mode, "abort-listen"), String.eq(mode, "close"))
    case Con{_,Con{+mode,Con{port,Nil{}}}}:
      choose_peer(String.eq(mode, "dial"), String.eq(mode, "dial-wrong-key"), port)
    case _:
      IO.die(Unit, 2, "usage: direct-check listen | dial PORT")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
