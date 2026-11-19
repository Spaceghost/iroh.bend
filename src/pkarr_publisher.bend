import Base
import ./bencode.bend as Ben
import ./discovery.bend as Dns
import ./ed25519.bend as Ed
import ./pkarr.bend as Pkarr
import ./pkarr_http.bend as Http

type Publisher is Data:
  Publishing{updates: Chan(List<&2,Dns.Attribute>), finished: Chan(Unit)}

type Destination is Data:
  ToRelay{url: String, timeout_ms: U32}

type Settings is Data:
  Schedule{ttl: U32, repeat_ms: U32}

type Worker is Data:
  ServePublisher{seed: List<&2,U32>, key: List<&2,U32>, target: Destination,
    settings: Settings, updates: Chan(List<&2,Dns.Attribute>)}

type Attempt is Data:
  LastAttempt{stamp: List<&2,U32>, failures: U32}

def defaults() -> Settings:
  Schedule{30,300000}

def pkarr_timestamp() -> IO(Result<&1,&1,U32 & String,List<&2,U32>>):
  import "./pkarr_publisher.c"

def increment_reversed(stamp: List<&2,U32>) -> List<&2,U32>:
  match stamp:
    case Con{255,tail}:
      Con{0,increment_reversed(tail)}
    case Con{byte,tail}:
      Con{U32.inc(byte),tail}
    case Nil{}:
      []

def choose_stamp(current: List<&2,U32>, last: List<&2,U32>, newer: Bool) -> List<&2,U32>:
  match newer:
    case True{}:
      current
    case False{}:
      List.reverse(&2,U32,increment_reversed(List.reverse(&2,U32,last)))

def next_stamp(+current: List<&2,U32>, +last: List<&2,U32>) -> List<&2,U32>:
  choose_stamp(current,last,Ben.less(last,current))

def write_signed(target: Destination, key: List<&2,U32>, packet: Result<&1,&1,U32 & String,List<&2,U32>>)
    -> IO(Result<&1,&1,U32 & String,Unit>):
  match target packet:
    case ToRelay{url,ms} Done{wire}:
      Http.publish(url,key,wire,ms)
    case _ Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Unit>,Fail{error})

def attempted(result: Result<&1,&1,U32 & String,Unit>, stamp: List<&2,U32>, failures: U32) -> Attempt:
  match result:
    case Done{_}:
      LastAttempt{stamp,0}
    case Fail{_}:
      LastAttempt{stamp,U32.inc(failures)}

def with_clock(worker: Worker, records: List<&2,Dns.Attribute>, last: Attempt,
    clock: Result<&1,&1,U32 & String,List<&2,U32>>) -> IO(Attempt):
  match worker last clock:
    case _ LastAttempt{stamp,failures} Fail{_}:
      IO.pure(Attempt,LastAttempt{stamp,U32.inc(failures)})
    case ServePublisher{seed,+key,target,Schedule{ttl,_},_} LastAttempt{stamp,failures} Done{now}:
      +fresh = next_stamp(now,stamp)
      do IO<Attempt>:
        packet : Result<&1,&1,U32 & String,List<&2,U32>> <- Pkarr.sign(seed,key,fresh,records,ttl)
        result : Result<&1,&1,U32 & String,Unit> <- write_signed(target,key,packet)
        return attempted(result,fresh,failures)

def wait_ms(settings: Settings, attempt: Attempt) -> U32:
  match settings attempt:
    case Schedule{_,period} LastAttempt{_,0}:
      period
    case _ LastAttempt{_,failures}:
      U32.mul(U32.min(failures,4294967),1000)

def latest_result(records: List<&2,Dns.Attribute>, event: Poll<&1,&1,Maybe<&1,List<&2,Dns.Attribute>>,Unit>,
    publish: List<&2,Dns.Attribute> -> IO(Unit),
    advance: List<&2,Dns.Attribute> -> (List<&2,Dns.Attribute> -> IO(Unit)) -> IO(Unit)) -> IO(Unit):
  match event:
    case Ready{Some{updated}}:
      advance(updated,publish)
    case Ready{None{}}:
      IO.pure(Unit,Unit{})
    case Wait{_}:
      publish(records)

def latest(+fuel: Nat, +updates: Chan(List<&2,Dns.Attribute>), records: List<&2,Dns.Attribute>,
    publish: List<&2,Dns.Attribute> -> IO(Unit)) -> IO(Unit):
  match fuel:
    case 0n:
      publish(records)
    case 1n+left:
      do IO<Unit>:
        event : Poll<&1,&1,Maybe<&1,List<&2,Dns.Attribute>>,Unit> <- Chan.try_recv(List<&2,Dns.Attribute>,updates,0)
        latest_result(records,event,publish,updated => next => latest(left,updates,updated,next))

def react(updates: Chan(List<&2,Dns.Attribute>), records: List<&2,Dns.Attribute>,
    event: Poll<&1,&1,Maybe<&1,List<&2,Dns.Attribute>>,Unit>, publish: List<&2,Dns.Attribute> -> IO(Unit)) -> IO(Unit):
  match event:
    case Ready{Some{updated}}:
      latest(64n,updates,updated,publish)
    case Ready{None{}}:
      IO.pure(Unit,Unit{})
    case Wait{_}:
      publish(records)

# The actor waits for updates or a deadline until the owner closes the channel.
@unsafe def loop(+worker: Worker, +records: List<&2,Dns.Attribute>, previous: Attempt) -> IO(Unit):
  ServePublisher{_,_,_,settings,+updates} = worker
  do IO<Unit>:
    time : Result<&1,&1,U32 & String,List<&2,U32>> <- pkarr_timestamp()
    +last : Attempt <- with_clock(worker,records,previous,time)
    event : Poll<&1,&1,Maybe<&1,List<&2,Dns.Attribute>>,Unit> <-
      Chan.try_recv(List<&2,Dns.Attribute>,updates,wait_ms(settings,last))
    react(updates,records,event,updated => loop(worker,updated,last))

def initial(worker: Worker, first: Maybe<&1,List<&2,Dns.Attribute>>) -> IO(Unit):
  match first:
    case Some{records}:
      loop(worker,records,LastAttempt{[],0})
    case None{}:
      IO.pure(Unit,Unit{})

def run(+worker: Worker) -> IO(Unit):
  ServePublisher{_,_,_,_,updates} = worker
  do IO<Unit>:
    first : Maybe<&1,List<&2,Dns.Attribute>> <- Chan.recv(List<&2,Dns.Attribute>,updates)
    initial(worker,first)

def started(seed: List<&2,U32>, settings: Settings, target: Destination,
    key: Result<&1,&1,U32 & String,List<&2,U32>>) -> IO(Result<&1,&1,U32 & String,Publisher>):
  match key:
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Publisher>,Fail{error})
    case Done{public_key}:
      do IO<Result<&1,&1,U32 & String,Publisher>>:
        +updates : Chan(List<&2,Dns.Attribute>) <- Chan.new(List<&2,Dns.Attribute>,1)
        finished : Chan(Unit) <- IO.fork(Unit,run(ServePublisher{seed,public_key,target,settings,updates}))
        return Done{Publishing{updates,finished}}

def start(+seed: List<&2,U32>, target: Destination, +settings: Settings)
    -> IO(Result<&1,&1,U32 & String,Publisher>):
  match settings:
    case Schedule{_,0}:
      IO.pure(Result<&1,&1,U32 & String,Publisher>,Fail{(1,"Pkarr publication interval must be positive")})
    case _:
      do IO<Result<&1,&1,U32 & String,Publisher>>:
        key : Result<&1,&1,U32 & String,List<&2,U32>> <- Ed.public_key(seed)
        started(seed,settings,target,key)

# Updates are sent to the worker without waiting for network I/O.
def update(publisher: Publisher, records: List<&2,Dns.Attribute>) -> IO(Unit):
  Publishing{updates,_} = publisher
  IO.spawn(Result<&1,&1,List<&2,Dns.Attribute>,Unit>,Chan.send(List<&2,Dns.Attribute>,updates,records))

def stop(publisher: Publisher) -> IO(Unit):
  Publishing{updates,finished} = publisher
  do IO<Unit>:
    Chan.close(List<&2,Dns.Attribute>,updates)
    IO.join(Unit,finished)
