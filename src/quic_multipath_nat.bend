import Base
import ./quic_multipath.bend as Quic
import ./quic_nat.bend as Wire
import ./quic_nat_retry.bend as Retry
import ./quic_nat_state.bend as State

type Probe is Data:
  Probe{ip: List<&2,U32>, port: U32, initial_rtt: U32, schedule: Retry.Schedule,
    challenges: List<&2,List<&2,U32>>}

type Progress is Data:
  Pending{probe: Probe}
  Answered{port: U32}
  TimedOut{}
  Failed{code: U32, message: String}

def for_address(ip: Wire.Address, port: U32, now: U32, initial_rtt: U32) -> Probe:
  match ip:
    case Wire.IPv4{bytes}:
      Probe{bytes,port,initial_rtt,Retry.start(now),[]}
    case Wire.IPv6{bytes}:
      Probe{bytes,port,initial_rtt,Retry.start(now),[]}

def start(target: State.Candidate, initial_rtt: U32) -> IO(Probe):
  State.Socket{ip,port} = target
  do IO<Probe>:
    now : U32 <- Quic.multipath_micros()
    return for_address(State.canonical(ip),port,now,initial_rtt)

type Response is Data:
  Unanswered{}
  Verified{}
  ReadError{code: U32, message: String}

def response_result(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>,
    wait: Quic.MultipathConnection -> IO(Quic.MultipathConnection & Response))
    -> IO(Quic.MultipathConnection & Response):
  match pair:
    case (conn,Done{1}):
      IO.pure(Quic.MultipathConnection & Response,(conn,Verified{}))
    case (conn,Done{_}):
      wait(conn)
    case (conn,Fail{(code,message)}):
      IO.pure(Quic.MultipathConnection & Response,(conn,ReadError{code,message}))

def poll_responses(tokens: List<&2,List<&2,U32>>, conn: Quic.MultipathConnection, +ip: List<&2,U32>, +port: U32)
    -> IO(Quic.MultipathConnection & Response):
  match tokens:
    case Nil{}:
      IO.pure(Quic.MultipathConnection & Response,(conn,Unanswered{}))
    case Con{token,rest}:
      do IO<Quic.MultipathConnection & Response>:
        pair : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <-
          Quic.take_multipath_nat_response(conn,ip,port,token)
        response_result(pair,next => poll_responses(rest,next,ip,port))

def result(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>, original: Probe, sent: Probe)
    -> (Quic.MultipathConnection & Progress):
  match pair:
    case (conn,Done{1}):
      (conn,Pending{sent})
    case (conn,Done{_}):
      (conn,Pending{original})
    case (conn,Fail{(code,message)}):
      (conn,Failed{code,message})

def send_token(conn: Quic.MultipathConnection, probe: Probe, +now: U32, +token: List<&2,U32>)
    -> IO(Quic.MultipathConnection & Progress):
  Probe{+ip,+port,+rtt,+schedule,+tokens} = probe
  do IO<Quic.MultipathConnection & Progress>:
    pair : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <-
      Quic.send_multipath_nat_challenge(conn,ip,port,token)
    return result(pair,Probe{ip,port,rtt,schedule,tokens},
      Probe{ip,port,rtt,Retry.confirmed_send(schedule,now),Con{token,tokens}})

def random_challenge(conn: Quic.MultipathConnection, probe: Probe, now: U32,
    high: Result<&1,&1,U32 & String,U32>, low: Result<&1,&1,U32 & String,U32>)
    -> IO(Quic.MultipathConnection & Progress):
  match high low:
    case Done{a} Done{b}:
      send_token(conn,probe,now,Con{26,Wire.append_word(a,Wire.append_word(b,[]))})
    case Fail{(code,message)} _:
      IO.pure(Quic.MultipathConnection & Progress,(conn,Failed{code,message}))
    case _ Fail{(code,message)}:
      IO.pure(Quic.MultipathConnection & Progress,(conn,Failed{code,message}))

def follow(status: Quic.MultipathConnection & Response, probe: Probe, now: U32, action: Retry.Action)
    -> IO(Quic.MultipathConnection & Progress):
  match status action:
    case (conn,Verified{}) _:
      Probe{_,port,_,_,_} = probe
      IO.pure(Quic.MultipathConnection & Progress,(conn,Answered{port}))
    case (conn,ReadError{code,message}) _:
      IO.pure(Quic.MultipathConnection & Progress,(conn,Failed{code,message}))
    case (conn,Unanswered{}) Retry.SendProbe{}:
      do IO<Quic.MultipathConnection & Progress>:
        high : Result<&1,&1,U32 & String,U32> <- IO.random_u32()
        low : Result<&1,&1,U32 & String,U32> <- IO.random_u32()
        random_challenge(conn,probe,now,high,low)
    case (conn,Unanswered{}) _:
      IO.pure(Quic.MultipathConnection & Progress,(conn,Pending{probe}))

def run_poll(conn: Quic.MultipathConnection, probe: Probe, now: U32, action: Retry.Action)
    -> IO(Quic.MultipathConnection & Progress):
  match probe action:
    case _ Retry.Expire{}:
      IO.pure(Quic.MultipathConnection & Progress,(conn,TimedOut{}))
    case Probe{+ip,+port,rtt,schedule,+tokens} next:
      do IO<Quic.MultipathConnection & Progress>:
        status : Quic.MultipathConnection & Response <- poll_responses(tokens,conn,ip,port)
        follow(status,Probe{ip,port,rtt,schedule,tokens},now,next)

def poll_at(conn: Quic.MultipathConnection, probe: Probe, +now: U32) -> IO(Quic.MultipathConnection & Progress):
  Probe{ip,port,+rtt,+schedule,tokens} = probe
  run_poll(conn,Probe{ip,port,rtt,schedule,tokens},now,Retry.action(schedule,now,rtt))

# Drive QUIC with step_multipath between calls. A response can match any
# challenge still in the round, including an earlier attempt.
def poll(conn: Quic.MultipathConnection, probe: Probe) -> IO(Quic.MultipathConnection & Progress):
  do IO<Quic.MultipathConnection & Progress>:
    now : U32 <- Quic.multipath_micros()
    poll_at(conn,probe,now)

def send_encoded_address(conn: Quic.MultipathConnection, encoded: Maybe<&2,List<&2,U32>>)
    -> IO(Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>):
  match encoded:
    case Some{bytes}:
      Quic.send_multipath_nat_address(conn,bytes)
    case None{}:
      IO.pure(Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>,
        (conn,Fail{(22,"invalid NAT address frame")}))

# Submit one candidate update from quic_nat_send.bend. Drive the connection
# between polls and keep the same frame until it is acknowledged.
def send_address(conn: Quic.MultipathConnection, frame: Wire.Frame)
    -> IO(Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>):
  send_encoded_address(conn,Wire.encode(frame))


def local_address(result: Quic.MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32> & U32>)
    -> (Quic.MultipathConnection & Result<&1,&1,U32 & String,State.Candidate>):
  match result:
    case (conn,Done{([a,b,c,d],port)}):
      (conn,Done{State.Socket{Wire.IPv4{[a,b,c,d]},port}})
    case (conn,Done{(bytes,port)}):
      (conn,Done{State.Socket{Wire.IPv6{bytes},port}})
    case (conn,Fail{error}):
      (conn,Fail{error})

def local_candidate(conn: Quic.MultipathConnection)
    -> IO(Quic.MultipathConnection & Result<&1,&1,U32 & String,State.Candidate>):
  do IO<Quic.MultipathConnection & Result<&1,&1,U32 & String,State.Candidate>>:
    result : Quic.MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32> & U32> <-
      Quic.multipath_nat_local_candidate(conn)
    return local_address(result)
