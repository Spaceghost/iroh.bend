import Base

type Schedule is Data:
  Retry{started: U32, last_sent: U32, sent: U32}

type Action is Data:
  SendProbe{}
  WaitForResponse{}
  Expire{}

def start(+now: U32) -> Schedule:
  Retry{now,now,0}

# Iroh 1.5 uses initial_rtt/10, then base, base, 2*base, 4*base, ...
# The interval caps at 2 seconds. Units are monotonic microseconds.
def delay_exponent(+sent: U32) -> U32:
  U32.sub(U32.clamp(sent,2,9),2)

def delay(initial_rtt: U32, sent: U32) -> U32:
  base = U32.min(U32.div(initial_rtt,10),2000000)
  factor = U32.shln(1,U32.to_nat(delay_exponent(sent)))
  U32.min(U32.mul(base,factor),2000000)

def choose(expired: Bool, send: Bool) -> Action:
  match expired send:
    case True{} _:
      Expire{}
    case False{} True{}:
      SendProbe{}
    case False{} False{}:
      WaitForResponse{}

# Unsigned subtraction handles the wrapping microsecond clock since
# both the retry interval and round timeout are below half its range.
def action(schedule: Schedule, +now: U32, initial_rtt: U32) -> Action:
  Retry{started,last,+sent} = schedule
  choose(U32.is_ge(U32.sub(now,started),30000000),
    U32.is_eq(sent,0) || (U32.is_lt(sent,9) && U32.is_ge(U32.sub(now,last),delay(initial_rtt,sent))))

def confirmed_send(schedule: Schedule, now: U32) -> Schedule:
  Retry{started,_,sent} = schedule
  Retry{started,now,U32.add(sent,1)}
