import Base
import ../src/quic_multipath.bend as Quic

def peer() -> List<&2,U32>:
  [25,127,107,35,225,108,133,50,198,171,200,56,250,205,94,167,
   137,190,12,118,178,146,3,52,3,155,250,139,61,54,141,97]

def unattached(conn: Quic.MultipathConnection, handle: Quic.MultipathSession,
    second: Maybe<&1,Quic.MultipathSession>, resume: Quic.MultipathSession -> IO(Unit)) -> IO(Unit):
  match second:
    case None{}:
      do IO<Unit>:
        Quic.close_multipath(conn)
        resume(handle)
    case Some{duplicate}:
      do IO<Unit>:
        Quic.close_multipath(conn)
        Quic.drop_multipath_session(handle)
        Quic.drop_multipath_session(duplicate)
        IO.die(Unit,1,"a session ticket was handed out twice")

def check_duplicate(result: Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathSession>>,
    ticket: Quic.MultipathSession, resume: Quic.MultipathSession -> IO(Unit)) -> IO(Unit):
  match result:
    case (conn,Done{remaining}):
      unattached(conn,ticket,remaining,resume)
    case (conn,Fail{(_,error)}):
      do IO<Unit>:
        Quic.close_multipath(conn)
        Quic.drop_multipath_session(ticket)
        IO.die(Unit,1,error)

def finished(present: Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathSession>>,
    retry: Quic.MultipathConnection -> (Quic.MultipathSession -> IO(Unit)) -> IO(Unit),
    resume: Quic.MultipathSession -> IO(Unit)) -> IO(Unit):
  match present:
    case (conn,Done{None{}}):
      do IO<Unit>:
        IO.sleep(1)
        retry(conn,resume)
    case (conn,Done{Some{ticket}}):
      do IO<Unit>:
        remaining : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathSession>> <-
          Quic.take_multipath_session(conn)
        check_duplicate(remaining,ticket,resume)
    case (conn,Fail{(_,error)}):
      do IO<Unit>:
        Quic.close_multipath(conn)
        IO.die(Unit,1,error)

def step(progress: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>,
    retry: Quic.MultipathConnection -> (Quic.MultipathSession -> IO(Unit)) -> IO(Unit),
    resume: Quic.MultipathSession -> IO(Unit)) -> IO(Unit):
  match progress:
    case (conn,Done{_}):
      do IO<Unit>:
        session : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathSession>> <-
          Quic.take_multipath_session(conn)
        finished(session,retry,resume)
    case (conn,Fail{(_,error)}):
      do IO<Unit>:
        Quic.close_multipath(conn)
        IO.die(Unit,1,error)

def wait_ticket(fuel: Nat, conn: Quic.MultipathConnection, resume: Quic.MultipathSession -> IO(Unit)) -> IO(Unit):
  match fuel:
    case 0n:
      do IO<Unit>:
        Quic.close_multipath(conn)
        IO.die(Unit,1,"upstream Iroh did not issue a session ticket")
    case 1n+left:
      do IO<Unit>:
        progress : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.step_multipath(conn)
        step(progress,next => keep => wait_ticket(left,next,keep),resume)

def first(result: Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathSession>>,
    resume: Quic.MultipathSession -> IO(Unit))
    -> IO(Unit):
  match result:
    case (conn,Done{None{}}):
      wait_ticket(4000n,conn,resume)
    case (conn,Done{Some{ticket}}):
      do IO<Unit>:
        Quic.drop_multipath_session(ticket)
        Quic.close_multipath(conn)
        IO.die(Unit,1,"a ticket was available before the pinned handshake")
    case (conn,Fail{(_,error)}):
      do IO<Unit>:
        Quic.close_multipath(conn)
        IO.die(Unit,1,error)

def reported(conn: Quic.MultipathConnection, +expected: U32, actual: U32, good: Bool) -> IO(Unit):
  match good:
    case True{}:
      do IO<Unit>:
        Quic.close_multipath(conn)
        IO.print("PASS authenticated Picoquic TLS resumption status " ++ U32.show(actual))
    case False{}:
      do IO<Unit>:
        Quic.close_multipath(conn)
        IO.die(Unit,1,"expected resumption status " ++ U32.show(expected) ++ ", got " ++ U32.show(actual))

def check_resume(result: Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>, +expected: U32,
    retry: Quic.MultipathConnection -> IO(Unit)) -> IO(Unit):
  match result:
    case (conn,Done{Some{+status}}):
      reported(conn,expected,status,U32.is_eq(status,expected))
    case (conn,Done{None{}}):
      do IO<Unit>:
        IO.sleep(1)
        retry(conn)
    case (conn,Fail{(_,error)}):
      do IO<Unit>:
        Quic.close_multipath(conn)
        IO.die(Unit,1,error)

def resume_step(progress: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>, expected: U32,
    retry: Quic.MultipathConnection -> IO(Unit)) -> IO(Unit):
  match progress:
    case (conn,Done{_}):
      do IO<Unit>:
        result : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>> <-
          Quic.multipath_resumption_status(conn)
        check_resume(result,expected,retry)
    case (conn,Fail{(_,error)}):
      do IO<Unit>:
        Quic.close_multipath(conn)
        IO.die(Unit,1,error)

def wait_resume(fuel: Nat, conn: Quic.MultipathConnection, +expected: U32) -> IO(Unit):
  match fuel:
    case 0n:
      do IO<Unit>:
        Quic.close_multipath(conn)
        IO.die(Unit,1,"the resumed handshake timed out")
    case 1n+left:
      do IO<Unit>:
        progress : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.step_multipath(conn)
        resume_step(progress,expected,next => wait_resume(left,next,expected))

def local_seed(mode: U32) -> List<&2,U32>:
  match mode:
    case 2:
      List.replicate(U32,32n,74)
    case _:
      List.replicate(U32,32n,73)

def peer_key(mode: U32) -> List<&2,U32>:
  match mode:
    case 3:
      List.replicate(U32,32n,0)
    case _:
      peer()

def offered_alpn(mode: U32) -> List<&2,U32>:
  match mode:
    case 4:
      [105,114,111,104,45,98,101,110,100,47,99,111,109,112,97,116,47,50]
    case 5:
      [0,105,114,111,104,45,98,101,110,100,47,99,111,109,112,97,116,47,49,255]
    case _:
      [105,114,111,104,45,98,101,110,100,47,99,111,109,112,97,116,47,49]

def warm_alpn(mode: U32) -> List<&2,U32>:
  match mode:
    case 5:
      offered_alpn(5)
    case _:
      offered_alpn(1)

def expected_status(mode: U32) -> U32:
  match mode:
    case 5:
      1
    case _:
      mode

def check_start(result: Quic.ConnectResult(), expected: U32, deny: Bool) -> IO(Unit):
  match result deny:
    case Done{conn} False{}:
      wait_resume(4000n,conn,expected)
    case Done{conn} True{}:
      do IO<Unit>:
        Quic.close_multipath(conn)
        IO.die(Unit,1,"an unrelated handshake accepted the session ticket")
    case Fail{(13,_)} True{}:
      IO.print("PASS Picoquic refused a session ticket for a different handshake")
    case Fail{(_,error)} _:
      IO.die(Unit,1,error)

def resume(host: String, port: U32, ticket: Quic.MultipathSession, +expected: U32) -> IO(Unit):
  do IO<Unit>:
    started : Quic.ConnectResult() <- Quic.start_multipath_resume(
      host,port,local_seed(expected),peer_key(expected),offered_alpn(expected),ticket)
    check_start(started,expected_status(expected),U32.is_ge(expected,2) && U32.is_le(expected,4))

def dial(+host: String, port: U32, target: U32, +expected: U32) -> IO(Unit):
  do IO<Unit>:
    conn : Quic.MultipathConnection <- IO.try(Quic.MultipathConnection,
      Quic.start_multipath_bytes(host,port,List.replicate(U32,32n,73),peer(),warm_alpn(expected)))
    session : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathSession>> <-
      Quic.take_multipath_session(conn)
    first(session,ticket => resume(host,target,ticket,expected))

def numbers(port: Maybe<&2,U32>, target: Maybe<&2,U32>, expected: Maybe<&2,U32>, host: String) -> IO(Unit):
  match port target expected:
    case Some{warm} Some{again} Some{state}:
      dial(host,warm,again,state)
    case _ _ _:
      IO.die(Unit,1,"invalid Iroh listener port or status")

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,host,port,target,expected]:
      numbers(U32.read(port),U32.read(target),U32.read(expected),host)
    case _:
      IO.die(Unit,1,"expected Iroh host, two ports and resumption status")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
