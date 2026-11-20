import Base
import ./quic_multipath.bend as Quic
import ./quic_nat.bend as Wire
import ./quic_nat_retry.bend as Retry
import ./quic_nat_state.bend as State
import ./quic_nat_send.bend as Send

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


def open_address(conn: Quic.MultipathConnection, ip: Wire.Address, port: U32)
    -> IO(Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>):
  match ip:
    case Wire.IPv4{bytes}:
      Quic.open_multipath_nat_path(conn,bytes,port)
    case Wire.IPv6{bytes}:
      Quic.open_multipath_nat_path(conn,bytes,port)

def open_path(conn: Quic.MultipathConnection, peer: State.Candidate)
    -> IO(Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>):
  State.Socket{ip,port} = peer
  open_address(conn,State.canonical(ip),port)

type CandidateProbe is Data:
  Trying{address: State.Candidate, probe: Probe}

type Phase is Data:
  Waiting{}
  Sending{frames: List<&2,Wire.Frame>, targets: List<&2,State.Candidate>}
  Probing{jobs: List<&2,CandidateProbe>}
  Opening{address: State.Candidate, remaining: List<&2,CandidateProbe>}
  Validating{path: U32, since: U32, remaining: List<&2,CandidateProbe>}
  DirectPath{path: U32}

type Dialer is Data:
  Unavailable{}
  Dialer{peer: State.PeerState, local: Send.LocalState, ipv6: Bool, dirty: Bool, phase: Phase}

def DialerResult() -> Type:
  Result<&1,&1,U32 & String,Dialer>

def NewPathResult() -> Type:
  Result<&1,&1,U32 & String,Maybe<&1,U32>>

def ipv6_socket(address: State.Candidate) -> Bool:
  match address:
    case State.Socket{Wire.IPv6{_},_}:
      True{}
    case _:
      False{}

def initialize_local(conn: Quic.MultipathConnection, local: Send.Change, peer: State.PeerState, ipv6: Bool)
    -> (Quic.MultipathConnection & DialerResult()):
  match local:
    case Send.Changed{state,Send.Updated{}}:
      (conn,Done{Dialer{peer,state,ipv6,False{},Waiting{}}})
    case _:
      (conn,Fail{(22,"could not register the local NAT candidate")})

def initialize_address(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,State.Candidate>,
    +local: U32, +remote: U32) -> (Quic.MultipathConnection & DialerResult()):
  match pair:
    case (conn,Done{+target}):
      initialize_local(conn,Send.add(Send.start(State.Client{},True{},Some{local},Some{remote}),target),
        State.start(State.Client{},True{},Some{local},Some{remote}),ipv6_socket(target))
    case (conn,Fail{error}):
      (conn,Fail{error})

def initialize_peer(conn: Quic.MultipathConnection, local: U32, remote: Wire.ParameterResult)
    -> IO(Quic.MultipathConnection & DialerResult()):
  match remote:
    case Wire.ParameterLimit{limit}:
      do IO<Quic.MultipathConnection & DialerResult()>:
        ours : Quic.MultipathConnection & Result<&1,&1,U32 & String,State.Candidate> <- local_candidate(conn)
        return initialize_address(ours,local,limit)
    case Wire.ParameterAbsent{}:
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Done{Unavailable{}}))
    case Wire.ParameterMalformed{}:
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Fail{(22,"peer sent an invalid NAT traversal limit")}))

def initialize_parameters(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>>, local: U32)
    -> IO(Quic.MultipathConnection & DialerResult()):
  match pair:
    case (conn,Done{bytes}):
      initialize_peer(conn,local,Wire.read_parameters(bytes))
    case (conn,Fail{error}):
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Fail{error}))

def initialize_ready(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>, local: U32)
    -> IO(Quic.MultipathConnection & DialerResult()):
  match pair:
    case (conn,Done{2}):
      do IO<Quic.MultipathConnection & DialerResult()>:
        params : Quic.MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>> <- Quic.peer_multipath_parameters(conn)
        initialize_parameters(params,local)
    case (conn,Done{1}):
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Done{Unavailable{}}))
    case (conn,Done{_}):
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Fail{(11,"QUIC handshake is incomplete")}))
    case (conn,Fail{error}):
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Fail{error}))

# Initialize after an opted-in dial. Use the same limit as the TLS offer.
def initialize(conn: Quic.MultipathConnection, local_limit: U32) -> IO(Quic.MultipathConnection & DialerResult()):
  do IO<Quic.MultipathConnection & DialerResult()>:
    ready : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.step_multipath(conn)
    initialize_ready(ready,local_limit)

def start_round(attempt: Send.RoundResult, peer: State.PeerState, ipv6: Bool) -> Dialer:
  match attempt:
    case Send.Round{state,Send.RoundStarted{_,frames,Con{target,rest}}}:
      Dialer{peer,state,ipv6,False{},Sending{frames,Con{target,rest}}}
    case Send.Round{state,_}:
      Dialer{peer,state,ipv6,False{},Waiting{}}

def advance_waiting(+peer: State.PeerState, local: Send.LocalState, +ipv6: Bool, dirty: Bool) -> Dialer:
  match dirty:
    case True{}:
      start_round(Send.begin(local,peer,ipv6),peer,ipv6)
    case False{}:
      Dialer{peer,local,ipv6,False{},Waiting{}}

def begin_probes(targets: List<&2,State.Candidate>, +now: U32) -> List<&2,CandidateProbe>:
  match targets:
    case Nil{}:
      []
    case Con{State.Socket{+ip,+port},rest}:
      Con{Trying{State.Socket{ip,port},for_address(State.canonical(ip),port,now,333000)},begin_probes(rest,now)}

def sending_result(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>,
    pending: Dialer, submitted: Dialer)
    -> (Quic.MultipathConnection & DialerResult()):
  match pair:
    case (conn,Done{1}):
      (conn,Done{submitted})
    case (conn,Done{_}):
      (conn,Done{pending})
    case (conn,Fail{error}):
      (conn,Fail{error})

def opening_result(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,U32>>,
    peer: State.PeerState, local: Send.LocalState, ipv6: Bool, dirty: Bool, address: State.Candidate,
    remaining: List<&2,CandidateProbe>, now: U32) -> (Quic.MultipathConnection & DialerResult()):
  match pair:
    case (conn,Done{Some{path}}):
      (conn,Done{Dialer{peer,local,ipv6,dirty,Validating{path,now,remaining}}})
    case (conn,Done{None{}}):
      (conn,Done{Dialer{peer,local,ipv6,dirty,Opening{address,remaining}}})
    case (conn,Fail{_}):
      (conn,Done{Dialer{peer,local,ipv6,dirty,Probing{remaining}}})

def path_result(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>, peer: State.PeerState,
    local: Send.LocalState, ipv6: Bool, dirty: Bool, path: U32, since: U32,
    remaining: List<&2,CandidateProbe>) -> (Quic.MultipathConnection & DialerResult()):
  match pair:
    case (conn,Done{1}):
      (conn,Done{Dialer{peer,local,ipv6,dirty,DirectPath{path}}})
    case (conn,Done{0}):
      (conn,Done{Dialer{peer,local,ipv6,dirty,Validating{path,since,remaining}}})
    case (conn,Done{_}):
      (conn,Done{Dialer{peer,local,ipv6,dirty,Probing{remaining}}})
    case (conn,Fail{error}):
      (conn,Fail{error})

def known_candidate(+address: State.Candidate, entries: List<&2,State.Advertisement>) -> Bool:
  match entries:
    case Nil{}:
      False{}
    case Con{State.Advertised{_,current},rest}:
      State.equal_socket(address,current) || known_candidate(address,rest)

def advertised(address: State.Candidate, state: State.PeerState) -> Bool:
  match state:
    case State.ClientState{_,entries}:
      known_candidate(Send.canonical_socket(address),entries)
    case _:
      False{}

def probe_progress(pair: Quic.MultipathConnection & Progress, peer: State.PeerState, local: Send.LocalState,
    ipv6: Bool, dirty: Bool, target: State.Candidate, rest: List<&2,CandidateProbe>)
    -> (Quic.MultipathConnection & DialerResult()):
  match pair:
    case (conn,Answered{_}):
      (conn,Done{Dialer{peer,local,ipv6,dirty,Opening{target,rest}}})
    case (conn,Pending{probe}):
      (conn,Done{Dialer{peer,local,ipv6,dirty,Probing{List.append(&2,CandidateProbe,rest,[Trying{target,probe}])}}})
    case (conn,_):
      (conn,Done{Dialer{peer,local,ipv6,dirty,Probing{rest}}})

def poll_candidate(conn: Quic.MultipathConnection, peer: State.PeerState, local: Send.LocalState,
    ipv6: Bool, dirty: Bool, target: State.Candidate, job: Probe, rest: List<&2,CandidateProbe>,
    now: U32, still_advertised: Bool) -> IO(Quic.MultipathConnection & DialerResult()):
  match still_advertised:
    case True{}:
      do IO<Quic.MultipathConnection & DialerResult()>:
        progress : Quic.MultipathConnection & Progress <- poll_at(conn,job,now)
        return probe_progress(progress,peer,local,ipv6,dirty,target,rest)
    case False{}:
      IO.pure(Quic.MultipathConnection & DialerResult(),
        (conn,Done{Dialer{peer,local,ipv6,dirty,Probing{rest}}}))

def open_candidate(conn: Quic.MultipathConnection, peer: State.PeerState, local: Send.LocalState,
    ipv6: Bool, dirty: Bool, +target: State.Candidate, remaining: List<&2,CandidateProbe>,
    now: U32, still_advertised: Bool) -> IO(Quic.MultipathConnection & DialerResult()):
  match still_advertised:
    case True{}:
      do IO<Quic.MultipathConnection & DialerResult()>:
        opened : Quic.MultipathConnection & NewPathResult() <- open_path(conn,target)
        return opening_result(opened,peer,local,ipv6,dirty,target,remaining,now)
    case False{}:
      IO.pure(Quic.MultipathConnection & DialerResult(),
        (conn,Done{Dialer{peer,local,ipv6,dirty,Probing{remaining}}}))

def after_retire(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,Unit>, next: Dialer)
    -> (Quic.MultipathConnection & DialerResult()):
  match pair:
    case (conn,Done{_}):
      (conn,Done{next})
    case (conn,Fail{error}):
      (conn,Fail{error})

def validate_path(conn: Quic.MultipathConnection, peer: State.PeerState, local: Send.LocalState,
    ipv6: Bool, dirty: Bool, +path: U32, since: U32, remaining: List<&2,CandidateProbe>,
    expired: Bool) -> IO(Quic.MultipathConnection & DialerResult()):
  match expired:
    case True{}:
      do IO<Quic.MultipathConnection & DialerResult()>:
        retired : Quic.MultipathConnection & Result<&1,&1,U32 & String,Unit> <- Quic.retire_multipath_path(conn,path)
        return after_retire(retired,Dialer{peer,local,ipv6,dirty,Probing{remaining}})
    case False{}:
      do IO<Quic.MultipathConnection & DialerResult()>:
        status : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.multipath_status(conn,path)
        return path_result(status,peer,local,ipv6,dirty,path,since,remaining)

def advance_phase(conn: Quic.MultipathConnection, state: Dialer, +now: U32)
    -> IO(Quic.MultipathConnection & DialerResult()):
  match state:
    case Dialer{peer,local,ipv6,dirty,Waiting{}}:
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Done{advance_waiting(peer,local,ipv6,dirty)}))
    case Dialer{peer,local,ipv6,dirty,Sending{Nil{},targets}}:
      IO.pure(Quic.MultipathConnection & DialerResult(),
        (conn,Done{Dialer{peer,local,ipv6,dirty,Probing{begin_probes(targets,now)}}}))
    case Dialer{+peer,+local,+ipv6,+dirty,Sending{Con{+frame,+rest},+targets}}:
      do IO<Quic.MultipathConnection & DialerResult()>:
        sent : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- send_address(conn,frame)
        return sending_result(sent,Dialer{peer,local,ipv6,dirty,Sending{Con{frame,rest},targets}},
          Dialer{peer,local,ipv6,dirty,Sending{rest,targets}})
    case Dialer{peer,local,ipv6,dirty,Probing{Nil{}}}:
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Done{advance_waiting(peer,local,ipv6,dirty)}))
    case Dialer{+peer,local,ipv6,dirty,Probing{Con{Trying{+target,job},rest}}}:
      poll_candidate(conn,peer,local,ipv6,dirty,target,job,rest,now,advertised(target,peer))
    case Dialer{+peer,local,ipv6,dirty,Opening{+target,remaining}}:
      open_candidate(conn,peer,local,ipv6,dirty,target,remaining,now,advertised(target,peer))
    case Dialer{peer,local,ipv6,dirty,Validating{path,+since,remaining}}:
      validate_path(conn,peer,local,ipv6,dirty,path,since,remaining,U32.is_ge(U32.sub(now,since),30000000))
    case unchanged:
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Done{unchanged}))

def accept_update(conn: Quic.MultipathConnection, change: State.Transition, local: Send.LocalState,
    ipv6: Bool, dirty: Bool, phase: Phase, now: U32)
    -> IO(Quic.MultipathConnection & DialerResult()):
  match change:
    case State.Received{peer,State.AddressAdded{_}}:
      advance_phase(conn,Dialer{peer,local,ipv6,True{},phase},now)
    case State.Received{peer,State.AddressRemoved{_}}:
      advance_phase(conn,Dialer{peer,local,ipv6,dirty,phase},now)
    case State.Received{peer,State.Ignored{}}:
      advance_phase(conn,Dialer{peer,local,ipv6,dirty,phase},now)
    case _:
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Fail{(22,"unexpected NAT traversal frame at the dialer")}))

def update_frame(conn: Quic.MultipathConnection, incoming: Wire.DecodeResult, peer: State.PeerState,
    local: Send.LocalState, ipv6: Bool, dirty: Bool, phase: Phase, now: U32)
    -> IO(Quic.MultipathConnection & DialerResult()):
  match incoming:
    case Wire.Decoded{frame,Nil{}}:
      accept_update(conn,State.receive(peer,frame),local,ipv6,dirty,phase,now)
    case _:
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Fail{(22,"invalid NAT traversal frame")}))

def drive_frame(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>,
    state: Dialer, now: U32) -> IO(Quic.MultipathConnection & DialerResult()):
  match pair state:
    case (conn,Done{Some{wire}}) Dialer{peer,local,ipv6,dirty,phase}:
      update_frame(conn,Wire.decode(wire),peer,local,ipv6,dirty,phase,now)
    case (conn,Done{_}) current:
      advance_phase(conn,current,now)
    case (conn,Fail{error}) _:
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Fail{error}))

def drive_ready(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>, state: Dialer)
    -> IO(Quic.MultipathConnection & DialerResult()):
  match pair state:
    case (conn,Done{_}) Unavailable{}:
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Done{Unavailable{}}))
    case (conn,Done{2}) active:
      do IO<Quic.MultipathConnection & DialerResult()>:
        now : U32 <- Quic.multipath_micros()
        incoming : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>> <-
          Quic.read_multipath_nat_frame(conn)
        drive_frame(incoming,active,now)
    case (conn,Done{_}) current:
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Done{current}))
    case (conn,Fail{error}) _:
      IO.pure(Quic.MultipathConnection & DialerResult(),(conn,Fail{error}))

# Poll bounded work alongside application I/O.
def step_dialer(conn: Quic.MultipathConnection, state: Dialer) -> IO(Quic.MultipathConnection & DialerResult()):
  do IO<Quic.MultipathConnection & DialerResult()>:
    ready : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.step_multipath(conn)
    drive_ready(ready,state)

def direct_path(state: Dialer) -> Maybe<&1,U32>:
  match state:
    case Dialer{_,_,_,_,DirectPath{path}}:
      Some{path}
    case _:
      None{}


def Connection() -> Type:
  Quic.MultipathConnection & Dialer

def ConnectResult() -> Type:
  Result<&1,&1,U32 & String,Connection()>

def initialized(pair: Quic.MultipathConnection & DialerResult()) -> IO(ConnectResult()):
  match pair:
    case (conn,Done{state}):
      IO.pure(ConnectResult(),Done{(conn,state)})
    case (conn,Fail{error}):
      do IO<ConnectResult()>:
        Quic.close_multipath(conn)
        return Fail{error}

def connected(result: Quic.ConnectResult(), limit: U32) -> IO(ConnectResult()):
  match result:
    case Done{conn}:
      do IO<ConnectResult()>:
        state : Quic.MultipathConnection & DialerResult() <- initialize(conn,limit)
        initialized(state)
    case Fail{error}:
      IO.pure(ConnectResult(),Fail{error})

def connect(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>, alpn: List<&2,U32>,
    +limit: U32, timeout: Nat) -> IO(ConnectResult()):
  do IO<ConnectResult()>:
    result : Quic.ConnectResult() <- Quic.connect_multipath_bytes_with_nat_limit(host,port,seed,peer,alpn,limit,timeout)
    connected(result,limit)

def driven(pair: Quic.MultipathConnection & DialerResult(), previous: Dialer)
    -> (Connection() & NewPathResult()):
  match pair:
    case (conn,Done{+state}):
      ((conn,state),Done{direct_path(state)})
    case (conn,Fail{error}):
      ((conn,previous),Fail{error})

def step(connection: Connection()) -> IO(Connection() & NewPathResult()):
  (conn,+state) = connection
  do IO<Connection() & NewPathResult()>:
    updated : Quic.MultipathConnection & DialerResult() <- step_dialer(conn,state)
    return driven(updated,state)


type ListenerDriver is Data:
  ListenerUnavailable{}
  ListenerDriver{peer: State.PeerState, local: Send.LocalState, frames: List<&2,Wire.Frame>,
    jobs: List<&2,CandidateProbe>}

def ListenerConnection() -> Type:
  Quic.MultipathConnection & ListenerDriver

def ListenerResult() -> Type:
  Result<&1,&1,U32 & String,ListenerConnection()>

def ListenerProgress() -> Type:
  ListenerConnection() & Result<&1,&1,U32 & String,Maybe<&1,State.Candidate>>

def listener_change(peer: State.PeerState, frames: List<&2,Wire.Frame>, jobs: List<&2,CandidateProbe>,
    change: Send.Change) -> ListenerDriver & Result<&1,&1,U32 & String,Unit>:
  match change:
    case Send.Changed{local,Send.Send{frame}}:
      (ListenerDriver{peer,local,List.append(&2,Wire.Frame,frames,[frame]),jobs},Done{Unit{}})
    case Send.Changed{local,Send.Unchanged{}}:
      (ListenerDriver{peer,local,frames,jobs},Done{Unit{}})
    case Send.Changed{local,Send.AddressLimit{}}:
      (ListenerDriver{peer,local,frames,jobs},Fail{(28,"peer NAT candidate limit reached")})
    case Send.Changed{local,_}:
      (ListenerDriver{peer,local,frames,jobs},Fail{(22,"invalid NAT candidate")})

# Allow one complete turnover of the maximum advertised candidate set.
def listener_queue_room(frames: List<&2,Wire.Frame>) -> Bool:
  Nat.is_lt(List.length(&2,Wire.Frame,frames),510n)

def apply_listener_change(+peer: State.PeerState, +local: Send.LocalState, +frames: List<&2,Wire.Frame>,
    +jobs: List<&2,CandidateProbe>, address: State.Candidate,
    change: Send.LocalState -> State.Candidate -> Send.Change, room: Bool)
    -> ListenerDriver & Result<&1,&1,U32 & String,Unit>:
  match room:
    case True{}:
      listener_change(peer,frames,jobs,change(local,address))
    case False{}:
      (ListenerDriver{peer,local,frames,jobs},Fail{(105,"NAT candidate update queue is full")})

def change_listener(state: ListenerDriver, address: State.Candidate,
    change: Send.LocalState -> State.Candidate -> Send.Change)
    -> ListenerDriver & Result<&1,&1,U32 & String,Unit>:
  match state:
    case ListenerDriver{peer,local,+frames,jobs}:
      apply_listener_change(peer,local,frames,jobs,address,change,listener_queue_room(frames))
    case ListenerUnavailable{}:
      (ListenerUnavailable{},Fail{(95,"NAT traversal was not negotiated")})

def keep_listener(conn: Quic.MultipathConnection, pair: ListenerDriver & Result<&1,&1,U32 & String,Unit>)
    -> ListenerConnection() & Result<&1,&1,U32 & String,Unit>:
  (state,result) = pair
  ((conn,state),result)

# Queue a reachable candidate on this listener socket.
def advertise_listener(connection: ListenerConnection(), address: State.Candidate)
    -> ListenerConnection() & Result<&1,&1,U32 & String,Unit>:
  (conn,state) = connection
  keep_listener(conn,change_listener(state,address,local => target => Send.add(local,target)))

def withdraw_listener(connection: ListenerConnection(), address: State.Candidate)
    -> ListenerConnection() & Result<&1,&1,U32 & String,Unit>:
  (conn,state) = connection
  keep_listener(conn,change_listener(state,address,Send.remove))

def close_listener_connection(conn: Quic.MultipathConnection, error: U32 & String) -> IO(ListenerResult()):
  do IO<ListenerResult()>:
    Quic.close_multipath(conn)
    return Fail{error}

def listener_parameters(conn: Quic.MultipathConnection, +local: U32, remote: Wire.ParameterResult,
    ipv6: Bool) -> IO(ListenerResult()):
  match remote:
    case Wire.ParameterLimit{+limit}:
      IO.pure(ListenerResult(),Done{(conn,ListenerDriver{
        State.start(State.Server{ipv6},True{},Some{local},Some{limit}),
        Send.start(State.Server{False{}},True{},Some{local},Some{limit}),[],[]})})
    case Wire.ParameterAbsent{}:
      IO.pure(ListenerResult(),Done{(conn,ListenerUnavailable{})})
    case Wire.ParameterMalformed{}:
      close_listener_connection(conn,(22,"peer sent an invalid NAT traversal limit"))

def listener_peer(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>>,
    limit: U32, ipv6: Bool) -> IO(ListenerResult()):
  match pair:
    case (conn,Done{bytes}):
      listener_parameters(conn,limit,Wire.read_parameters(bytes),ipv6)
    case (conn,Fail{error}):
      close_listener_connection(conn,error)

def listener_ready(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>,
    limit: U32, ipv6: Bool) -> IO(ListenerResult()):
  match pair:
    case (conn,Done{2}):
      do IO<ListenerResult()>:
        params : Quic.MultipathConnection & Result<&1,&1,U32 & String,List<&2,U32>> <- Quic.peer_multipath_parameters(conn)
        listener_peer(params,limit,ipv6)
    case (conn,Done{1}):
      IO.pure(ListenerResult(),Done{(conn,ListenerUnavailable{})})
    case (conn,Done{_}):
      close_listener_connection(conn,(11,"QUIC handshake is incomplete"))
    case (conn,Fail{error}):
      close_listener_connection(conn,error)

# Initialize an accepted connection with the receive limit from its TLS offer.
# The caller supplies its reachable socket addresses through advertise_listener.
def initialize_listener(conn: Quic.MultipathConnection, limit: U32, ipv6: Bool) -> IO(ListenerResult()):
  do IO<ListenerResult()>:
    ready : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.step_multipath(conn)
    listener_ready(ready,limit,ipv6)

def NatListener() -> Type:
  Quic.MultipathListener & U32

def BindListenerResult() -> Type:
  Result<&1,&1,U32 & String,NatListener() & U32>

def AcceptListenerResult() -> Type:
  NatListener() & Result<&1,&1,U32 & String,Maybe<&1,ListenerConnection()>>

def bound_listener(result: Result<&1,&1,U32 & String,Quic.MultipathListener & U32>, limit: U32)
    -> BindListenerResult():
  match result:
    case Done{(listener,port)}:
      Done{((listener,limit),port)}
    case Fail{error}:
      Fail{error}

def bind_listener_offer(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>, limit: U32, parameter: Maybe<&2,List<&2,U32>>) -> IO(BindListenerResult()):
  match parameter:
    case Some{encoded}:
      do IO<BindListenerResult()>:
        result : Result<&1,&1,U32 & String,Quic.MultipathListener & U32> <-
          Quic.bind_multipath_alpns_nat_offer(host,port,seed,peer,alpns,encoded)
        return bound_listener(result,limit)
    case None{}:
      IO.pure(BindListenerResult(),Fail{(22,"invalid NAT traversal limit")})

# List opaque ALPN byte strings in server preference order.
def bind_listener(host: String, port: U32, seed: List<&2,U32>, peer: List<&2,U32>,
    alpns: List<&2,List<&2,U32>>, +limit: U32) -> IO(BindListenerResult()):
  bind_listener_offer(host,port,seed,peer,alpns,limit,Wire.encode_limit(limit))

def accept_listener_state(result: ListenerResult(), listener: NatListener()) -> AcceptListenerResult():
  match result:
    case Done{connection}:
      (listener,Done{Some{connection}})
    case Fail{error}:
      (listener,Fail{error})

def accept_listener_address(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,State.Candidate>,
    listener: Quic.MultipathListener, +limit: U32) -> IO(AcceptListenerResult()):
  match pair:
    case (conn,Done{address}):
      do IO<AcceptListenerResult()>:
        result : ListenerResult() <- initialize_listener(conn,limit,ipv6_socket(address))
        return accept_listener_state(result,(listener,limit))
    case (conn,Fail{error}):
      do IO<AcceptListenerResult()>:
        Quic.close_multipath(conn)
        return ((listener,limit),Fail{error})

def accept_listener_result(pair: Quic.MultipathListener &
    Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>>, limit: U32) -> IO(AcceptListenerResult()):
  match pair:
    case (listener,Done{Some{conn}}):
      do IO<AcceptListenerResult()>:
        address : Quic.MultipathConnection & Result<&1,&1,U32 & String,State.Candidate> <- local_candidate(conn)
        accept_listener_address(address,listener,limit)
    case (listener,Done{None{}}):
      IO.pure(AcceptListenerResult(),((listener,limit),Done{None{}}))
    case (listener,Fail{error}):
      IO.pure(AcceptListenerResult(),((listener,limit),Fail{error}))

def accept_listener(owner: NatListener()) -> IO(AcceptListenerResult()):
  (listener,limit) = owner
  do IO<AcceptListenerResult()>:
    received : Quic.MultipathListener & Result<&1,&1,U32 & String,Maybe<&1,Quic.MultipathConnection>> <-
      Quic.accept_multipath(listener)
    accept_listener_result(received,limit)

def close_listener(owner: NatListener()) -> IO(Unit):
  (listener,_) = owner
  Quic.close_multipath_listener(listener)

def listener_updates_pending(state: ListenerDriver) -> Bool:
  match state:
    case ListenerDriver{_,_,Con{_,_},_}:
      True{}
    case _:
      False{}

def listener_probe_result(pair: Quic.MultipathConnection & Progress, peer: State.PeerState, local: Send.LocalState,
    frames: List<&2,Wire.Frame>, rest: List<&2,CandidateProbe>, target: State.Candidate) -> ListenerProgress():
  match pair:
    case (conn,Pending{job}):
      ((conn,ListenerDriver{peer,local,frames,List.append(&2,CandidateProbe,rest,[Trying{target,job}])}),Done{None{}})
    case (conn,Answered{_}):
      ((conn,ListenerDriver{peer,local,frames,rest}),Done{Some{target}})
    case (conn,_):
      ((conn,ListenerDriver{peer,local,frames,rest}),Done{None{}})

def listener_poll(conn: Quic.MultipathConnection, peer: State.PeerState, local: Send.LocalState,
    frames: List<&2,Wire.Frame>, jobs: List<&2,CandidateProbe>, now: U32) -> IO(ListenerProgress()):
  match jobs:
    case Nil{}:
      IO.pure(ListenerProgress(),((conn,ListenerDriver{peer,local,frames,[]}),Done{None{}}))
    case Con{Trying{target,job},rest}:
      do IO<ListenerProgress()>:
        result : Quic.MultipathConnection & Progress <- poll_at(conn,job,now)
        return listener_probe_result(result,peer,local,frames,rest,target)

def listener_sent(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>, peer: State.PeerState,
    local: Send.LocalState, +frame: Wire.Frame, +rest: List<&2,Wire.Frame>, +jobs: List<&2,CandidateProbe>,
    now: U32) -> IO(ListenerProgress()):
  match pair:
    case (conn,Done{1}):
      listener_poll(conn,peer,local,rest,jobs,now)
    case (conn,Done{_}):
      listener_poll(conn,peer,local,Con{frame,rest},jobs,now)
    case (conn,Fail{error}):
      IO.pure(ListenerProgress(),((conn,ListenerDriver{peer,local,Con{frame,rest},jobs}),Fail{error}))

def listener_advance(conn: Quic.MultipathConnection, state: ListenerDriver, now: U32) -> IO(ListenerProgress()):
  match state:
    case ListenerDriver{peer,local,Nil{},jobs}:
      listener_poll(conn,peer,local,[],jobs,now)
    case ListenerDriver{peer,local,Con{+frame,rest},jobs}:
      do IO<ListenerProgress()>:
        sent : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- send_address(conn,frame)
        listener_sent(sent,peer,local,frame,rest,jobs,now)
    case ListenerUnavailable{}:
      IO.pure(ListenerProgress(),((conn,ListenerUnavailable{}),Done{None{}}))

def add_listener_probe(target: State.Candidate, jobs: List<&2,CandidateProbe>, restart: Bool, now: U32)
    -> List<&2,CandidateProbe>:
  match restart:
    case True{}:
      begin_probes([target],now)
    case False{}:
      List.append(&2,CandidateProbe,jobs,begin_probes([target],now))

def listener_update(conn: Quic.MultipathConnection, change: State.Transition, local: Send.LocalState,
    frames: List<&2,Wire.Frame>, jobs: List<&2,CandidateProbe>, +now: U32) -> IO(ListenerProgress()):
  match change:
    case State.Received{peer,State.Probe{_,target,restart}}:
      listener_advance(conn,ListenerDriver{peer,local,frames,add_listener_probe(target,jobs,restart,now)},now)
    case State.Received{peer,State.Ignored{}}:
      listener_advance(conn,ListenerDriver{peer,local,frames,jobs},now)
    case State.Received{peer,_}:
      IO.pure(ListenerProgress(),((conn,ListenerDriver{peer,local,frames,jobs}),
        Fail{(22,"unexpected NAT traversal frame at the listener")}))

def listener_decode(conn: Quic.MultipathConnection, decoded: Wire.DecodeResult, state: ListenerDriver,
    now: U32) -> IO(ListenerProgress()):
  match decoded state:
    case Wire.Decoded{frame,Nil{}} ListenerDriver{peer,local,frames,jobs}:
      listener_update(conn,State.receive(peer,frame),local,frames,jobs,now)
    case _ current:
      IO.pure(ListenerProgress(),((conn,current),Fail{(22,"invalid NAT traversal frame")}))

def listener_frame(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>,
    state: ListenerDriver, now: U32) -> IO(ListenerProgress()):
  match pair:
    case (conn,Done{Some{wire}}):
      listener_decode(conn,Wire.decode(wire),state,now)
    case (conn,Done{None{}}):
      listener_advance(conn,state,now)
    case (conn,Fail{error}):
      IO.pure(ListenerProgress(),((conn,state),Fail{error}))

def listener_step_ready(pair: Quic.MultipathConnection & Result<&1,&1,U32 & String,U32>, state: ListenerDriver)
    -> IO(ListenerProgress()):
  match pair state:
    case (conn,Done{_}) ListenerUnavailable{}:
      IO.pure(ListenerProgress(),((conn,ListenerUnavailable{}),Done{None{}}))
    case (conn,Done{2}) active:
      do IO<ListenerProgress()>:
        now : U32 <- Quic.multipath_micros()
        incoming : Quic.MultipathConnection & Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>> <-
          Quic.read_multipath_nat_frame(conn)
        listener_frame(incoming,active,now)
    case (conn,Done{_}) current:
      IO.pure(ListenerProgress(),((conn,current),Done{None{}}))
    case (conn,Fail{error}) current:
      IO.pure(ListenerProgress(),((conn,current),Fail{error}))

# Poll one received frame, one outbound update and one retry. A reported
# candidate answered an authenticated off-path challenge on this connection.
def step_listener(connection: ListenerConnection()) -> IO(ListenerProgress()):
  (conn,state) = connection
  do IO<ListenerProgress()>:
    ready : Quic.MultipathConnection & Result<&1,&1,U32 & String,U32> <- Quic.step_multipath(conn)
    listener_step_ready(ready,state)
