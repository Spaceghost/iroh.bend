import Base
import ../src/discovery.bend as Dns
import ../src/pkarr.bend as Pkarr
import ../src/pkarr_http.bend as Http
import ../src/pkarr_publisher.bend as Publish
import ./pkarr.bend as Fixture

def publish(url: String) -> IO(Unit):
  do IO<Unit>:
    signed : List<&2,U32> <- IO.try(List<&2,U32>,
      Pkarr.sign(List.replicate(U32,32n,42),Fixture.key(),List.replicate(U32,8n,255),Fixture.records(),30))
    IO.try(Unit,Http.publish(url,Fixture.key(),signed,2500))
    IO.print("PASS Pkarr HTTP PUT")

def report_resolution(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("PASS Pkarr HTTP GET and signature verification")
    case False{}:
      IO.die(Unit,1,"Pkarr HTTP returned the wrong endpoint records")

def resolve(url: String) -> IO(Unit):
  do IO<Unit>:
    proof : Pkarr.Verification <- IO.try(Pkarr.Verification,Http.resolve(url,Fixture.key(),2500))
    report_resolution(Fixture.valid(proof))

def reject_tamper(proof: Pkarr.Verification) -> IO(Unit):
  match proof:
    case Pkarr.InvalidSignature{}:
      IO.print("PASS Pkarr HTTP signature rejection")
    case _:
      IO.die(Unit,1,"Pkarr HTTP accepted or misclassified the tampered response")

def tampered(url: String) -> IO(Unit):
  do IO<Unit>:
    proof : Pkarr.Verification <- IO.try(Pkarr.Verification,Http.resolve(url,Fixture.key(),2500))
    reject_tamper(proof)

def not_found(reply: Result<&1,&1,U32 & String,Pkarr.Verification>) -> IO(Unit):
  match reply:
    case Fail{(404,_)}:
      IO.print("PASS Pkarr HTTP 404")
    case _:
      IO.die(Unit,1,"expected a Pkarr HTTP 404")

def missing(url: String) -> IO(Unit):
  do IO<Unit>:
    reply : Result<&1,&1,U32 & String,Pkarr.Verification> <- Http.resolve(url,Fixture.key(),2500)
    not_found(reply)

def snapshot(result: Result<&1,&1,U32 & String,Pkarr.Verification>, expected: U32) -> Bool:
  match result:
    case Done{Pkarr.Verified{_,[Dns.UserData{[actual]}]}}:
      U32.is_eq(actual,expected)
    case _:
      False{}

def snapshot_result(ready: Bool, retry: Unit -> IO(Unit)) -> IO(Unit):
  match ready:
    case True{}:
      IO.pure(Unit,Unit{})
    case False{}:
      do IO<Unit>:
        IO.sleep(15)
        retry(Unit{})

def await_snapshot(fuel: Nat, +url: String, +expected: U32) -> IO(Unit):
  match fuel:
    case 0n:
      IO.die(Unit,1,"Pkarr publisher did not deliver the expected snapshot")
    case 1n+left:
      do IO<Unit>:
        result : Result<&1,&1,U32 & String,Pkarr.Verification> <- Http.resolve(url,Fixture.key(),300)
        snapshot_result(snapshot(result,expected),_ => await_snapshot(left,url,expected))

def republish(+url: String) -> IO(Unit):
  do IO<Unit>:
    +publisher : Publish.Publisher <- IO.try(Publish.Publisher,
      Publish.start(List.replicate(U32,32n,42),Publish.ToRelay{url,500},Publish.Schedule{30,120}))
    Publish.update(publisher,[Dns.UserData{[49]}])
    await_snapshot(200n,url,49)
    IO.sleep(300)
    Publish.update(publisher,[Dns.UserData{[50]}])
    await_snapshot(200n,url,50)
    Publish.stop(publisher)
    IO.print("publisher stopped")
    IO.sleep(250)

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{"publish",Con{url,Nil{}}}}:
      publish(url)
    case Con{_,Con{"resolve",Con{url,Nil{}}}}:
      resolve(url)
    case Con{_,Con{"missing",Con{url,Nil{}}}}:
      missing(url)
    case Con{_,Con{"tampered",Con{url,Nil{}}}}:
      tampered(url)
    case Con{_,Con{"republish",Con{url,Nil{}}}}:
      republish(url)
    case _:
      IO.die(Unit,2,"usage: pkarr-http-check publish|resolve|missing|tampered|republish relay-url")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
