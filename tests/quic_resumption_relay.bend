import Base

def finish_pair(-L: Type, -C: Type, pair: L & C, handle: C -> IO(Unit)) -> IO(L):
  (owner,conn) = pair
  do IO<L>:
    handle(conn)
    return owner

def exchange(-L: Type, -C: Type, owner: L, accept: L -> IO(L & C), handle: C -> IO(Unit)) -> IO(L):
  do IO<L>:
    pair : L & C <- accept(owner)
    finish_pair(L,C,pair,handle)

def handshakes(-L: Type, stage: String, owner: L, warm: L -> IO(L), resumed: L -> Bool -> IO(L)) -> IO(L):
  match stage:
    case "warm":
      warm(owner)
    case "reject":
      resumed(owner,False{})
    case "accept":
      do IO<L>:
        next : L <- warm(owner)
        resumed(next,True{})
    case _:
      IO.die(L,2,"unknown relay resumption mode")

@unsafe def listen(~L: Type, ~C: Type, ~accept: L -> IO(L & C), ~warm: C -> IO(Unit),
    ~resumed: C -> Bool -> IO(Unit), ~close: L -> IO(Result<&1,&1,U32 & String,Unit>),
    owner: L, port: U32, stage: String) -> IO(Unit):
  do IO<Unit>:
    IO.print(U32.show(port))
    done : L <- handshakes(L,stage,owner,listener => exchange(L,C,listener,accept,warm),
      listener => expected => exchange(L,C,listener,accept,conn => resumed(conn,expected)))
    IO.try(Unit,close(done))
