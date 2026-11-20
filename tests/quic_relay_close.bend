import Base
import ./quic_stream_cancel.bend as Stream
import ./quic_connection_close.bend as Close
import ../src/relay_quic.bend as Relay

def ready(-C: Type, raw: C & Result<&1,&1,U32 & String,U32>) -> IO(C):
  match raw:
    case (conn,Done{_}):
      IO.pure(C,conn)
    case (_,Fail{(code,message)}):
      IO.die(C,code,message)

def release(-C: Type, driver: Stream.Driver<C>, conn: C) -> IO(Unit):
  Stream.Driver{_,_,drop} = driver
  drop(conn)

@unsafe def finish(~C: Type, ~ops: Close.Operations<C>, ~driver: Stream.Driver<C>, conn: C, send: Bool, +id: U32) -> IO(Unit):
  match send:
    case True{}:
      do IO<Unit>:
        closed : C <- Close.first(~C,~ops,conn,True{},id)
        release(C,driver,closed)
        IO.print(String.append("PASS close ",U32.show(id)))
    case False{}:
      Close.finish_close(~C,~ops,driver,conn,False{},id)

@unsafe def exchange(~C: Type, ~ops: Close.Operations<C>, ~driver: Stream.Driver<C>, conn: C, +send: Bool, +id: U32) -> IO(Unit):
  do IO<Unit>:
    opened : C <- Stream.run_checks(~C,~driver,conn,0,1,Close.echo(send,Close.hello()),4000n)
    finish(~C,~ops,~driver,opened,send,id)

def accepted(-L: Type, -C: Type, raw: L & Result<&1,&1,U32 & String,Maybe<&1,C>>, retry: L -> IO(L & C)) -> IO(L & C):
  match raw:
    case (listener,Done{Some{conn}}):
      IO.pure(L & C,(listener,conn))
    case (listener,Done{None{}}):
      do IO<L & C>:
        IO.sleep(1)
        retry(listener)
    case (_,Fail{(code,message)}):
      IO.die(L & C,code,message)

@unsafe def accept(~L: Type, ~C: Type, ~poll: L -> IO(L & Result<&1,&1,U32 & String,Maybe<&1,C>>), listener: L, fuel: Nat) -> IO(L & C):
  match fuel:
    case 0n:
      IO.die(L & C,1,"relay-only listener timed out")
    case 1n+left:
      do IO<L & C>:
        raw : L & Result<&1,&1,U32 & String,Maybe<&1,C>> <- poll(listener)
        accepted(L,C,raw,next => accept(~L,~C,~poll,next,left))

def check_route(-C: Type, pair: C & Maybe<&1,Relay.Bridge>) -> IO(C & Maybe<&1,Relay.Bridge>):
  match pair:
    case (conn,Some{bridge}):
      IO.pure(C & Maybe<&1,Relay.Bridge>,(conn,Some{bridge}))
    case (_,None{}):
      IO.die(C & Maybe<&1,Relay.Bridge>,1,"expected the dialer to own its relay bridge")

def options(role: String, url: String, operation: String, id: Maybe<&2,U32>,
    listen: String -> Bool -> U32 -> IO(Unit), dial: String -> Bool -> U32 -> IO(Unit)) -> IO(Unit):
  match role operation id:
    case "listen" "send" Some{n}:
      listen(url,True{},n)
    case "listen" "receive" Some{n}:
      listen(url,False{},n)
    case "dial" "send" Some{n}:
      dial(url,True{},n)
    case "dial" "receive" Some{n}:
      dial(url,False{},n)
    case _ _ _:
      IO.die(Unit,2,"expected listen|dial URL send|receive CASE")

def command(args: List<String>, listen: String -> Bool -> U32 -> IO(Unit), dial: String -> Bool -> U32 -> IO(Unit)) -> IO(Unit):
  match args:
    case [_,role,url,op,id]:
      options(role,url,op,U32.read(id),listen,dial)
    case _:
      IO.die(Unit,2,"expected listen|dial URL send|receive CASE")
