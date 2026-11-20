import Base
import ./quic_handshake_routes.bend as Race
import ./relay_quic.bend as Path

# Each relay opener either transfers ownership to the dial or closes its bridge
# when the dial has already selected a path.
def Offer() -> Type:
  Result<&1,&1,U32 & String,Path.Bridge & U32>

type DialEvent<-A: Data> is Type:
  Lookup{answer: A}
  Relay{offer: Offer()}

type Workers<-A: Data> is Data:
  Workers{events: Chan(DialEvent<A>), stop: Chan(Unit), lookup_done: Chan(Unit), lookup_count: Nat}

def release(offer: Offer()) -> IO(Unit):
  match offer:
    case Done{(bridge,_)}:
      Race.stop(Some{bridge})
    case Fail{_}:
      IO.pure(Unit,Unit{})

def transferred(-A: Data, result: Result<&1,&1,DialEvent<A>,Unit>) -> IO(Unit):
  match result:
    case Fail{Relay{offer}}:
      release(offer)
    case _:
      IO.pure(Unit,Unit{})

def open_relay(~A: Data, url: String, seed: List<&2,U32>, peer: List<&2,U32>, events: Chan(DialEvent<A>)) -> IO(Unit):
  do IO<Unit>:
    offer : Offer() <- Path.start(url,seed,peer,0)
    sent : Result<&1,&1,DialEvent<A>,Unit> <- Chan.send(DialEvent<A>,events,Relay{offer})
    transferred(A,sent)

def start_relays(~A: Data, urls: List<&2,String>, +seed: List<&2,U32>, +peer: List<&2,U32>, +events: Chan(DialEvent<A>)) -> IO(Unit):
  match urls:
    case Nil{}:
      IO.pure(Unit,Unit{})
    case Con{url,rest}:
      do IO<Unit>:
        IO.spawn(Unit,open_relay(~A,url,seed,peer,events))
        start_relays(~A,rest,seed,peer,events)

def lookup(~A: Data, resolve: Chan(Unit) -> IO(A), workers: Workers<A>) -> IO(Unit):
  Workers{events,stop,done,_} = workers
  do IO<Unit>:
    answer : A <- resolve(stop)
    _ : Result<&1,&1,DialEvent<A>,Unit> <- Chan.send(DialEvent<A>,events,Lookup{answer})
    _ : Result<&1,&1,Unit,Unit> <- Chan.send(Unit,done,Unit{})
    return Unit{}

def create(~A: Data, +count: Nat) -> IO(Workers<A>):
  do IO<Workers<A>>:
    events : Chan(DialEvent<A>) <- Chan.new(DialEvent<A>,0)
    stop : Chan(Unit) <- Chan.new(Unit,0)
    done : Chan(Unit) <- Chan.new(Unit,U32.from_nat(count))
    return Workers{events,stop,done,count}

def joined(count: Nat, +done: Chan(Unit)) -> IO(Unit):
  match count:
    case 0n:
      Chan.close(Unit,done)
    case 1n+left:
      do IO<Unit>:
        _ : Maybe<&1,Unit> <- Chan.recv(Unit,done)
        joined(left,done)

def close(~A: Data, workers: Workers<A>) -> IO(Unit):
  Workers{events,stop,done,count} = workers
  do IO<Unit>:
    Chan.close(Unit,stop)
    Chan.close(DialEvent<A>,events)
    joined(count,done)

def contains(~A: Data, ~same: A -> A -> Bool, +value: A, seen: List<&2,A>) -> Bool:
  match seen:
    case Nil{}:
      False{}
    case Con{head,tail}:
      same(value,head) || contains(~A,~same,value,tail)

def keep(~A: Data, duplicate: Bool, +value: A, seen: List<&2,A>, resume: List<&2,A> -> List<&2,A>) -> List<&2,A>:
  match duplicate:
    case True{}:
      resume(seen)
    case False{}:
      Con{value,resume(Con{value,seen})}

def fresh(~A: Data, ~same: A -> A -> Bool, values: List<&2,A>, +seen: List<&2,A>) -> List<&2,A>:
  match values:
    case Nil{}:
      []
    case Con{+head,rest}:
      keep(~A,contains(~A,~same,head,seen),head,seen,next => fresh(~A,~same,rest,next))
