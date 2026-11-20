import Base

def Opened() -> Type:
  Result<&1,&1,U32 & String,Socket>

def lookup_tcp_start(host: String, port: U32) -> IO(Opened()):
  import "./lookup_socket.c"

def lookup_tcp_ready(socket: Socket) -> IO(Socket & Result<&1,&1,U32 & String,Bool>):
  import "./lookup_socket.c"

def close_error(socket: Socket, error: U32 & String) -> IO(Opened()):
  do IO<Opened()>:
    Socket.close(socket)
    return Fail{error}

def wake(event: Poll<&1,&1,Maybe<&1,Unit>,Unit>, socket: Socket, retry: Socket -> IO(Opened())) -> IO(Opened()):
  match event:
    case Wait{_}:
      retry(socket)
    case Ready{_}:
      close_error(socket,(1,"DNS TCP connection cancelled"))

def wait_connect(left: Nat, socket: Socket, stop: Chan(Unit), retry: Socket -> IO(Opened())) -> IO(Opened()):
  match left:
    case 0n:
      close_error(socket,(1,"DNS TCP connection timed out"))
    case 1n+k:
      do IO<Opened()>:
        event : Poll<&1,&1,Maybe<&1,Unit>,Unit> <- Chan.try_recv(Unit,stop,U32.min(10,U32.from_nat(1n+k)))
        wake(event,socket,retry)

def checked(ready: Socket & Result<&1,&1,U32 & String,Bool>, stop: Chan(Unit), deadline: Nat,
    retry: Socket -> IO(Opened())) -> IO(Opened()):
  match ready:
    case (socket,Done{True{}}):
      IO.pure(Opened(),Done{socket})
    case (socket,Done{False{}}):
      do IO<Opened()>:
        now : Nat <- IO.now()
        wait_connect(Nat.sub(deadline,now),socket,stop,retry)
    case (socket,Fail{error}):
      close_error(socket,error)

@unsafe def poll_connect(socket: Socket, +stop: Chan(Unit), +deadline: Nat) -> IO(Opened()):
  do IO<Opened()>:
    ready : Socket & Result<&1,&1,U32 & String,Bool> <- lookup_tcp_ready(socket)
    checked(ready,stop,deadline,next => poll_connect(next,stop,deadline))

def started(opened: Opened(), stop: Chan(Unit), deadline: Nat) -> IO(Opened()):
  match opened:
    case Done{socket}:
      poll_connect(socket,stop,deadline)
    case Fail{error}:
      IO.pure(Opened(),Fail{error})

def connect(stop: Chan(Unit), host: String, port: U32, ms: U32) -> IO(Opened()):
  do IO<Opened()>:
    now : Nat <- IO.now()
    opened : Opened() <- lookup_tcp_start(host,port)
    started(opened,stop,Nat.add(now,U32.to_nat(ms)))
