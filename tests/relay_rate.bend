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

def checked(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("PASS invalid configuration, millisecond rollover, exact exhaustion, notice deduplication, and saturated refill")
    case False{}:
      IO.die(Unit,1,"rate bucket boundary check failed")

def main() -> IO(Unit):
  checked(Bool.not(Rate.valid(Rate.ReceiveLimit{9,None{}})) &&
    Bool.not(Rate.valid(Rate.ReceiveLimit{200,Some{0}})) &&
    wrapped(Rate.consume(Rate.initial(Rate.ReceiveLimit{200,None{}},4294967250),4294967250,20)) &&
    U32.is_eq(Rate.fill_at(1,4294967295,429496729,42949672),4294967295))
