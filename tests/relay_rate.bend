import Base
import ../src/relay_rate.bend as Rate

def repeated(next: Rate.Charge) -> Bool:
  match next:
    case Rate.HoldReading{_,False{}}:
      True{}
    case _:
      False{}

def wrapped(charge: Rate.Charge) -> Bool:
  match charge:
    case Rate.HoldReading{+bucket,True{}}:
      Bool.not(Rate.ready(53,bucket)) && Rate.ready(54,bucket) &&
      repeated(Rate.consume(Rate.resume(bucket),54,20))
    case _:
      False{}

def fresh_hold(next: Rate.Charge) -> Bool:
  match next:
    case Rate.HoldReading{+bucket,True{}}:
      Bool.not(Rate.ready(1999,bucket)) && Rate.ready(2000,bucket)
    case _:
      False{}

def unlimited_preserves_notice(next: Rate.Charge) -> Bool:
  match next:
    case Rate.KeepReading{Rate.Unmetered{True{}}}:
      True{}
    case _:
      False{}

def live_reset(+limited: Rate.Limits, +old: Rate.Bucket) -> Bool:
  +cleared = Rate.reconfigure(Rate.Unlimited{},1900,old)
  unlimited_preserves_notice(Rate.consume(cleared,1900,65544)) &&
  repeated(Rate.consume(Rate.reconfigure(limited,1900,cleared),1900,20)) &&
  fresh_hold(Rate.consume(Rate.reconfigure(limited,1900,Rate.Unmetered{False{}}),1900,20))

def checked(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("PASS receive-limit boundaries, saturated refill, and live reset with notice deduplication")
    case False{}:
      IO.die(Unit,1,"rate bucket boundary check failed")

def main() -> IO(Unit):
  checked(Bool.not(Rate.valid(Rate.ReceiveLimit{9,None{}})) &&
    Bool.not(Rate.valid(Rate.ReceiveLimit{200,Some{0}})) &&
    wrapped(Rate.consume(Rate.initial(Rate.ReceiveLimit{200,None{}},4294967250),4294967250,20)) &&
    live_reset(Rate.ReceiveLimit{200,Some{20}},Rate.Paused{0,1,1,30000}) &&
    U32.is_eq(Rate.fill_at(1,4294967295,429496729,42949672),4294967295))
