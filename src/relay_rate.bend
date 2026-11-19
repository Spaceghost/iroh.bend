import Base
import ./relay_heartbeat.bend as Clock

type Limits is Data:
  Unlimited{}
  ReceiveLimit{bytes_per_second: U32, burst_bytes: Maybe<&2,U32>}

type Bucket is Data:
  Unmetered{}
  Reading{fill: U32, capacity: U32, refill: U32, last: U32, notified: Bool}
  Paused{fill: U32, capacity: U32, refill: U32, resume_at: U32}

type Charge is Data:
  KeepReading{bucket: Bucket}
  HoldReading{bucket: Bucket, first: Bool}

def capacity(burst: Maybe<&2,U32>, refill: U32) -> U32:
  match burst:
    case Some{size}:
      size
    case None{}:
      refill

def valid(limits: Limits) -> Bool:
  match limits:
    case Unlimited{}:
      True{}
    case ReceiveLimit{+rate,burst}:
      U32.is_ge(rate,10) && U32.is_gt(capacity(burst,U32.div(rate,10)),0)

def initial_bucket(+max: U32, refill: U32, now: U32) -> Bucket:
  Reading{max,max,refill,now,False{}}

def initial(limits: Limits, now: U32) -> Bucket:
  match limits:
    case Unlimited{}:
      Unmetered{}
    case ReceiveLimit{rate,burst}:
      +refill = U32.div(rate,10)
      initial_bucket(capacity(burst,refill),refill,now)

def metered(limits: Limits) -> Bool:
  match limits:
    case Unlimited{}:
      False{}
    case ReceiveLimit{_,_}:
      True{}

# Refills follow Iroh's 100 ms periods. Saturate before multiplying to
# keep the result in range even at the largest supported byte rate.
def capped_fill(+fill: U32, +max: U32, +refill: U32, +periods: U32, full: Bool) -> U32:
  match full:
    case True{}:
      max
    case False{}:
      U32.add(fill,U32.mul(refill,periods))

def fill_at(+fill: U32, +max: U32, +refill: U32, +periods: U32) -> U32:
  capped_fill(fill,max,refill,periods,U32.is_gt(periods,U32.div(U32.sub(max,fill),refill)))

def charged(+fill: U32, +max: U32, +refill: U32, +last: U32, +bytes: U32,
    notified: Bool, room: Bool) -> Charge:
  match room:
    case True{}:
      KeepReading{Reading{U32.sub(fill,bytes),max,refill,last,notified}}
    case False{}:
      +debt = U32.sub(bytes,fill)
      periods = U32.inc(U32.div(debt,refill))
      credit = U32.min(max,U32.sub(refill,U32.mod(debt,refill)))
      HoldReading{Paused{credit,max,refill,U32.add(last,U32.mul(periods,100))},Bool.not(notified)}

def refill_and_charge(fill: U32, +max: U32, +refill: U32, +last: U32, now: U32, +bytes: U32,
    notified: Bool) -> Charge:
  +periods = U32.div(U32.sub(now,last),100)
  +available = fill_at(fill,max,refill,periods)
  charged(available,max,refill,U32.add(last,U32.mul(periods,100)),bytes,notified,U32.is_gt(available,bytes))

def consume(bucket: Bucket, now: U32, bytes: U32) -> Charge:
  match bucket:
    case Unmetered{}:
      KeepReading{Unmetered{}}
    case Reading{fill,max,refill,last,notified}:
      refill_and_charge(fill,max,refill,last,now,bytes,notified)
    case Paused{fill,max,refill,next}:
      HoldReading{Paused{fill,max,refill,next},False{}}

def ready(now: U32, bucket: Bucket) -> Bool:
  match bucket:
    case Paused{_,_,_,deadline}:
      Clock.reached(now,deadline)
    case _:
      False{}

def resume(bucket: Bucket) -> Bucket:
  match bucket:
    case Paused{fill,max,refill,deadline}:
      Reading{fill,max,refill,deadline,True{}}
    case _:
      bucket
