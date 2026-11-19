import Base

type Probe is Data:
  Waiting{nonce: List<&2,U32>, sent: U32, timeout: U32}
  NonePending{}

type Heartbeat is Data:
  Timer{interval: U32, next_ping: U32, timeout: U32, probe: Probe}

type Action is Data:
  WaitForTraffic{}
  SendProbe{}
  ClosePeer{}

# Milliseconds wrap at 2^32. Deadlines are at most 20 seconds away.
def reached(now: U32, deadline: U32) -> Bool:
  U32.is_lt(U32.sub(now,deadline),2147483648)

def jitter(seed: U32) -> U32:
  U32.mul(U32.add(16,U32.mod(seed,5)),1000)

def initial(now: U32, random: U32) -> Heartbeat:
  +interval = jitter(random)
  Timer{interval,U32.add(now,interval),5000,NonePending{}}

def touch(timer: Heartbeat, now: U32) -> Heartbeat:
  Timer{+interval,_,timeout,probe} = timer
  Timer{interval,U32.add(now,interval),timeout,probe}

def start(timer: Heartbeat, +now: U32, random: U32, nonce: List<&2,U32>) -> Heartbeat:
  Timer{_,_,+timeout,_} = timer
  +interval = jitter(random)
  Timer{interval,U32.add(now,interval),timeout,Waiting{nonce,now,U32.add(now,timeout)}}

def ping_action(due: Bool) -> Action:
  match due:
    case True{}:
      SendProbe{}
    case False{}:
      WaitForTraffic{}

def timeout_action(due: Bool) -> Action:
  match due:
    case True{}:
      ClosePeer{}
    case False{}:
      WaitForTraffic{}

def action(timer: Heartbeat, now: U32) -> Action:
  match timer:
    case Timer{_,_,_,Waiting{_,_,timeout}}:
      timeout_action(reached(now,timeout))
    case Timer{_,next,_,NonePending{}}:
      ping_action(reached(now,next))

def same_nonce(bytes: List<&2,U32>, pong: List<&2,U32>) -> Bool:
  match bytes pong:
    case Nil{} Nil{}:
      True{}
    case Con{a,rest} Con{b,remaining}:
      U32.is_eq(a,b) && same_nonce(rest,remaining)
    case _ _:
      False{}

def measured(+probe: Probe, interval: U32, next: U32, timeout: U32, now: U32,
    matched: Bool) -> Heartbeat:
  match probe matched:
    case Waiting{_,sent,_} True{}:
      rtt = U32.min(U32.sub(now,sent),5000)
      Timer{interval,next,U32.min(5000,U32.max(500,U32.mul(3,rtt))),NonePending{}}
    case _ _:
      Timer{interval,next,timeout,probe}

def received_pong(timer: Heartbeat, +now: U32, bytes: List<&2,U32>) -> Heartbeat:
  match timer:
    case Timer{+interval,_,timeout,Waiting{+nonce,+sent,+deadline}}:
      measured(Waiting{nonce,sent,deadline},interval,U32.add(now,interval),timeout,now,same_nonce(nonce,bytes))
    case Timer{+interval,_,timeout,NonePending{}}:
      Timer{interval,U32.add(now,interval),timeout,NonePending{}}
