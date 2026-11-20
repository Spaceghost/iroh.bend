import Base
import ../src/quic_nat.bend as NatWire
import ../src/quic_nat_state.bend as State
import ../src/quic_nat_send.bend as Send

def bytes_equal(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(x,y) && bytes_equal(xs,ys)
    case _ _:
      False{}

def encoded(expected: List<&2,U32>, actual: Maybe<&2,List<&2,U32>>) -> Bool:
  match actual:
    case Some{bytes}:
      bytes_equal(expected,bytes)
    case None{}:
      False{}

def same_address(a: NatWire.Address, b: NatWire.Address) -> Bool:
  match a b:
    case NatWire.IPv4{x} NatWire.IPv4{y}:
      bytes_equal(x,y)
    case NatWire.IPv6{x} NatWire.IPv6{y}:
      bytes_equal(x,y)
    case _ _:
      False{}

def same_integer(a: NatWire.VarInt, b: NatWire.VarInt) -> Bool:
  NatWire.Var{hi,lo} = a
  NatWire.Var{other_hi,other_lo} = b
  U32.is_eq(hi,other_hi) && U32.is_eq(lo,other_lo)

def same_frame(a: NatWire.Frame, b: NatWire.Frame) -> Bool:
  match a b:
    case NatWire.AddAddress{seq,ip,port} NatWire.AddAddress{other_seq,other_ip,other_port}:
      same_integer(seq,other_seq) && same_address(ip,other_ip) && U32.is_eq(port,other_port)
    case NatWire.ReachOut{round,ip,port} NatWire.ReachOut{other_round,other_ip,other_port}:
      same_integer(round,other_round) && same_address(ip,other_ip) && U32.is_eq(port,other_port)
    case NatWire.RemoveAddress{seq} NatWire.RemoveAddress{other_seq}:
      same_integer(seq,other_seq)
    case _ _:
      False{}

def decoded(expected: NatWire.Frame, rest: List<&2,U32>, result: NatWire.DecodeResult) -> Bool:
  match result:
    case NatWire.Decoded{frame,tail}:
      same_frame(expected,frame) && bytes_equal(rest,tail)
    case _:
      False{}

def exact(+frame: NatWire.Frame, +wire: List<&2,U32>) -> Bool:
  encoded(wire,NatWire.encode(frame)) &&
    decoded(frame,[1,0],NatWire.decode(List.append(&2,U32,wire,[1,0])))

# The IPv4 ADD_ADDRESS, IPv6 REACH_OUT, and REMOVE_ADDRESS values match
# the noq-proto 1.5.0 roundtrip tests. Cover both address families for both tags.
def frame_vectors() -> Bool:
  +v4 = {NatWire.IPv4{[127,0,0,1]} : NatWire.Address}
  +v6 = {NatWire.IPv6{[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]} : NatWire.Address}
  +seq = {NatWire.Var{0,42} : NatWire.VarInt}
  exact(NatWire.AddAddress{seq,v4,4242},[128,61,127,144,42,127,0,0,1,16,146]) &&
  exact(NatWire.AddAddress{seq,v6,4242},[128,61,127,145,42,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,16,146]) &&
  exact(NatWire.ReachOut{seq,v4,4242},[128,61,127,146,42,127,0,0,1,16,146]) &&
  exact(NatWire.ReachOut{seq,v6,4242},[128,61,127,147,42,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,16,146]) &&
  exact(NatWire.RemoveAddress{NatWire.Var{0,10}},[128,61,127,148,10])

def sequence_vector(hi: U32, lo: U32, sequence: List<&2,U32>) -> Bool:
  exact(NatWire.RemoveAddress{NatWire.Var{hi,lo}},Con{128,Con{61,Con{127,Con{148,sequence}}}})

def sequence_vectors() -> Bool:
  sequence_vector(0,0,[0]) &&
  sequence_vector(0,63,[63]) &&
  sequence_vector(0,64,[64,64]) &&
  sequence_vector(0,16383,[127,255]) &&
  sequence_vector(0,16384,[128,0,64,0]) &&
  sequence_vector(0,1073741823,[191,255,255,255]) &&
  sequence_vector(0,1073741824,[192,0,0,0,64,0,0,0]) &&
  sequence_vector(1,305419896,[192,0,0,1,18,52,86,120]) &&
  sequence_vector(1073741823,4294967295,[255,255,255,255,255,255,255,255]) &&
  decoded(NatWire.RemoveAddress{NatWire.Var{0,10}},[],NatWire.decode([128,61,127,148,64,10]))

def result_code(result: NatWire.DecodeResult) -> U32:
  match result:
    case NatWire.ShortFrame{}:
      1
    case NatWire.InvalidFrame{}:
      2
    case NatWire.OtherFrame{}:
      3
    case NatWire.Decoded{_,_}:
      0

def reject(wire: List<&2,U32>, code: U32) -> Bool:
  U32.is_eq(result_code(NatWire.decode(wire)),code)

def absent(-A: Data, result: Maybe<&2,A>) -> Bool:
  match result:
    case None{}:
      True{}
    case Some{_}:
      False{}

def malformed_frames() -> Bool:
  reject([],1) &&
  reject([128,61,127],1) &&
  reject([128,61,127,148,192,0,0,0,0,0,0],1) &&
  reject([128,61,127,144,42,127,0,0],1) &&
  reject([128,61,127,145,42,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0],1) &&
  reject([128,61,127,146,42,127,0,0,1,16],1) &&
  reject([128,61,127,146,42,127,0,0,1,16,256],2) &&
  reject([128,61,127,144,42,127,0,256,1,16,146],2) &&
  reject([128,61,127,148,64,256],2) &&
  reject([192,0,0,0,0,61,127,148,10],2) &&
  reject([1],3) &&
  reject([128,61,127,149],3) &&
  absent(List<&2,U32>,NatWire.encode(NatWire.RemoveAddress{NatWire.Var{1073741824,0}})) &&
  absent(List<&2,U32>,NatWire.encode(NatWire.AddAddress{NatWire.Var{0,42},NatWire.IPv4{[127,0,0]},4242})) &&
  absent(List<&2,U32>,NatWire.encode(NatWire.AddAddress{NatWire.Var{0,42},NatWire.IPv4{[127,0,0,256]},4242})) &&
  absent(List<&2,U32>,NatWire.encode(NatWire.ReachOut{NatWire.Var{0,42},NatWire.IPv4{[127,0,0,1]},65536}))

def limit_equal(expected: U32, actual: Maybe<&2,U32>) -> Bool:
  match actual:
    case Some{value}:
      U32.is_eq(expected,value)
    case None{}:
      False{}

def exact_limit(+value: U32) -> Bool:
  encoded([192,0,61,127,145,18,4,1,1,value],NatWire.encode_limit(value)) &&
    limit_equal(value,NatWire.decode_limit([value]))

def parameter_vectors() -> Bool:
  exact_limit(1) && exact_limit(63) && exact_limit(64) && exact_limit(255) &&
  absent(U32,NatWire.decode_limit([])) &&
  absent(U32,NatWire.decode_limit([0])) &&
  absent(U32,NatWire.decode_limit([256])) &&
  absent(U32,NatWire.decode_limit([64,64])) &&
  absent(List<&2,U32>,NatWire.encode_limit(0)) &&
  absent(List<&2,U32>,NatWire.encode_limit(256))

type Exchange is Data:
  Incoming{frame: NatWire.Frame, expected: State.PeerEvent}

def check_event(expected: State.PeerEvent, actual: State.PeerEvent) -> Bool:
  match expected actual:
    case State.Ignored{} State.Ignored{}:
      True{}
    case State.ProtocolViolation{} State.ProtocolViolation{}:
      True{}
    case State.AddressAdded{address} State.AddressAdded{other}:
      State.equal_socket(address,other)
    case State.AddressRemoved{address} State.AddressRemoved{other}:
      State.equal_socket(address,other)
    case State.Probe{round,target,True{}} State.Probe{other,other_target,True{}}:
      same_integer(round,other) && State.equal_socket(target,other_target)
    case State.Probe{round,target,False{}} State.Probe{other,other_target,False{}}:
      same_integer(round,other) && State.equal_socket(target,other_target)
    case _ _:
      False{}

def check_transition(expected: State.PeerEvent, actual: State.Transition, next: State.PeerState -> Bool) -> Bool:
  State.Received{state,event} = actual
  check_event(expected,event) && next(state)

def exchange(steps: List<&2,Exchange>, state: State.PeerState) -> Bool:
  match steps:
    case Nil{}:
      True{}
    case Con{Incoming{frame,expected},rest}:
      check_transition(expected,State.receive(state,frame),next => exchange(rest,next))

def client_addresses() -> Bool:
  +v4 = {NatWire.IPv4{[127,0,0,1]} : NatWire.Address}
  +mapped = {NatWire.IPv6{[0,0,0,0,0,0,0,0,0,0,255,255,127,0,0,1]} : NatWire.Address}
  +v6 = {NatWire.IPv6{[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]} : NatWire.Address}
  +id = {NatWire.Var{0,42} : NatWire.VarInt}
  +other = {NatWire.Var{0,43} : NatWire.VarInt}
  exchange([
    Incoming{NatWire.AddAddress{id,v4,1},State.AddressAdded{State.Socket{v4,1}}},
    Incoming{NatWire.AddAddress{id,mapped,1},State.Ignored{}},
    Incoming{NatWire.AddAddress{other,v6,2},State.Ignored{}},
    Incoming{NatWire.AddAddress{id,v6,3},State.AddressAdded{State.Socket{v6,3}}},
    Incoming{NatWire.RemoveAddress{other},State.Ignored{}},
    Incoming{NatWire.RemoveAddress{id},State.AddressRemoved{State.Socket{v6,3}}},
    Incoming{NatWire.AddAddress{other,v6,2},State.AddressAdded{State.Socket{v6,2}}},
    Incoming{NatWire.ReachOut{id,v4,1},State.ProtocolViolation{}}
  ],State.start(State.Client{},True{},Some{1},Some{4})) &&
  exchange([
    Incoming{NatWire.AddAddress{id,v4,1},State.ProtocolViolation{}}
  ],State.start(State.Client{},True{},Some{1},None{})) &&
  exchange([
    Incoming{NatWire.AddAddress{id,v4,1},State.ProtocolViolation{}}
  ],State.start(State.Client{},False{},Some{1},Some{4}))

# The first round uses the same two addresses as noq-proto's
# test_basic_server_state. Verify round rollover and retransmission as well.
def server_reach_out() -> Bool:
  +v4 = {NatWire.IPv4{[127,0,0,1]} : NatWire.Address}
  +mapped = {NatWire.IPv6{[0,0,0,0,0,0,0,0,0,0,255,255,127,0,0,1]} : NatWire.Address}
  +other = {NatWire.IPv4{[1,1,1,1]} : NatWire.Address}
  +other_mapped = {NatWire.IPv6{[0,0,0,0,0,0,0,0,0,0,255,255,1,1,1,1]} : NatWire.Address}
  +round = {NatWire.Var{0,1} : NatWire.VarInt}
  +new_round = {NatWire.Var{1,0} : NatWire.VarInt}
  exchange([
    Incoming{NatWire.ReachOut{round,v4,1},State.Probe{round,State.Socket{mapped,1},True{}}},
    Incoming{NatWire.ReachOut{round,other,2},State.Probe{round,State.Socket{other_mapped,2},False{}}},
    Incoming{NatWire.ReachOut{round,mapped,1},State.Ignored{}},
    Incoming{NatWire.ReachOut{round,v4,3},State.ProtocolViolation{}},
    Incoming{NatWire.ReachOut{new_round,mapped,1},State.Probe{new_round,State.Socket{mapped,1},True{}}},
    Incoming{NatWire.ReachOut{round,other,2},State.Ignored{}},
    Incoming{NatWire.ReachOut{new_round,other,2},State.Probe{new_round,State.Socket{other_mapped,2},False{}}},
    Incoming{NatWire.AddAddress{round,v4,1},State.ProtocolViolation{}},
    Incoming{NatWire.RemoveAddress{round},State.ProtocolViolation{}}
  ],State.start(State.Server{True{}},True{},Some{2},Some{1}))

def ipv4_probes() -> Bool:
  +v4 = {NatWire.IPv4{[127,0,0,1]} : NatWire.Address}
  +mapped = {NatWire.IPv6{[0,0,0,0,0,0,0,0,0,0,255,255,127,0,0,1]} : NatWire.Address}
  +v6 = {NatWire.IPv6{[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]} : NatWire.Address}
  +first = {NatWire.Var{0,1} : NatWire.VarInt}
  +later = {NatWire.Var{0,3} : NatWire.VarInt}
  exchange([
    Incoming{NatWire.ReachOut{later,v6,1},State.Ignored{}},
    Incoming{NatWire.ReachOut{first,mapped,2},State.Probe{first,State.Socket{v4,2},True{}}}
  ],State.start(State.Server{False{}},True{},Some{2},Some{1}))

type LocalStep is Data:
  Add{candidate: State.Candidate, expected: Send.LocalEvent}
  Remove{candidate: State.Candidate, expected: Send.LocalEvent}

def check_local(expected: Send.LocalEvent, actual: Send.LocalEvent) -> Bool:
  match expected actual:
    case Send.Unchanged{} Send.Unchanged{}:
      True{}
    case Send.Updated{} Send.Updated{}:
      True{}
    case Send.AddressLimit{} Send.AddressLimit{}:
      True{}
    case Send.InvalidAddress{} Send.InvalidAddress{}:
      True{}
    case Send.NotNegotiated{} Send.NotNegotiated{}:
      True{}
    case Send.Send{frame} Send.Send{other}:
      same_frame(frame,other)
    case _ _:
      False{}

def local_transition(expected: Send.LocalEvent, actual: Send.Change, next: Send.LocalState -> Bool) -> Bool:
  Send.Changed{state,event} = actual
  check_local(expected,event) && next(state)

def local_steps(steps: List<&2,LocalStep>, state: Send.LocalState, finish: Send.LocalState -> Bool) -> Bool:
  match steps:
    case Nil{}:
      finish(state)
    case Con{Add{candidate,expected},rest}:
      local_transition(expected,Send.add(state,candidate),next => local_steps(rest,next,finish))
    case Con{Remove{candidate,expected},rest}:
      local_transition(expected,Send.remove(state,candidate),next => local_steps(rest,next,finish))

def server_send() -> Bool:
  +ip = {NatWire.IPv4{[127,0,0,1]} : NatWire.Address}
  +mapped = {NatWire.IPv6{[0,0,0,0,0,0,0,0,0,0,255,255,127,0,0,1]} : NatWire.Address}
  +first = {State.Socket{ip,1} : State.Candidate}
  +second = {State.Socket{ip,2} : State.Candidate}
  +same = {State.Socket{mapped,1} : State.Candidate}
  local_steps([
    Add{State.Socket{ip,65536},Send.InvalidAddress{}},
    Add{State.Socket{NatWire.IPv4{[127,0,1]},1},Send.InvalidAddress{}},
    Add{same,Send.Send{NatWire.AddAddress{NatWire.Var{0,0},ip,1}}},
    Add{first,Send.Unchanged{}},
    Add{second,Send.AddressLimit{}},
    Remove{second,Send.Unchanged{}},
    Remove{first,Send.Send{NatWire.RemoveAddress{NatWire.Var{0,0}}}},
    Add{second,Send.Send{NatWire.AddAddress{NatWire.Var{0,1},ip,2}}}
  ],Send.start(State.Server{True{}},True{},Some{5},Some{1}),_ => True{}) &&
  local_steps([
    Add{first,Send.NotNegotiated{}}
  ],Send.start(State.Server{True{}},False{},Some{5},Some{1}),_ => True{})

def verify_round(id: NatWire.VarInt, expected: NatWire.Frame, target: State.Candidate, result: Send.RoundResult,
    next: Send.LocalState -> Bool) -> Bool:
  match result:
    case Send.Round{state,Send.RoundStarted{round,[actual],[remote]}}:
      same_frame(expected,actual) && State.equal_socket(target,remote) &&
        same_integer(id,round) && next(state)
    case _:
      False{}

def verify_empty(result: Send.RoundResult) -> Bool:
  match result:
    case Send.Round{_,Send.NoLocalCandidates{}}:
      True{}
    case _:
      False{}

def client_send() -> Bool:
  +ip = {NatWire.IPv4{[127,0,0,1]} : NatWire.Address}
  +v6 = {NatWire.IPv6{[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]} : NatWire.Address}
  +remote = {State.Socket{NatWire.IPv4{[1,1,1,1]},2} : State.Candidate}
  +mapped = {State.Socket{NatWire.IPv6{[0,0,0,0,0,0,0,0,0,0,255,255,1,1,1,1]},2} : State.Candidate}
  +start = Send.start(State.Client{},True{},Some{5},Some{1})
  +peer = {State.ClientState{5,[
    State.Advertised{NatWire.Var{0,5},State.Socket{v6,3}},
    State.Advertised{NatWire.Var{0,6},remote},
    State.Advertised{NatWire.Var{0,7},remote}
  ]} : State.PeerState}
  +peer_v4 = {State.ClientState{5,[State.Advertised{NatWire.Var{0,6},remote}]} : State.PeerState}
  verify_empty(Send.begin(start,peer,False{})) &&
  local_steps([
    Add{State.Socket{ip,1},Send.Updated{}},
    Add{State.Socket{ip,1},Send.Unchanged{}},
    Add{State.Socket{ip,2},Send.AddressLimit{}}
  ],start,ready =>
    verify_round(NatWire.Var{0,1},NatWire.ReachOut{NatWire.Var{0,1},ip,1},remote,Send.begin(ready,peer,False{}),step =>
      verify_round(NatWire.Var{0,2},NatWire.ReachOut{NatWire.Var{0,2},ip,1},mapped,Send.begin(step,peer_v4,True{}),active =>
        local_steps([Remove{State.Socket{ip,1},Send.Updated{}}],active,
          empty => verify_empty(Send.begin(empty,peer,False{}))))))

def sequence_rollover() -> Bool:
  same_integer(NatWire.Var{1,0},Send.next(NatWire.Var{0,4294967295})) &&
  same_integer(NatWire.Var{1073741823,4294967295},Send.next(NatWire.Var{1073741823,4294967295}))

def require(message: String, ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print(String.append("PASS ",message))
    case False{}:
      IO.die(Unit,1,String.append("FAIL ",message))

def main() -> IO(Unit):
  do IO<Unit>:
    require("QUIC NAT traversal frame vectors",frame_vectors())
    require("QUIC NAT traversal sequence integer boundaries",sequence_vectors())
    require("QUIC NAT traversal malformed and unknown frames",malformed_frames())
    require("QUIC NAT traversal transport parameter",parameter_vectors())
    require("QUIC NAT traversal client candidate updates and role checks",client_addresses())
    require("QUIC NAT traversal server rounds and duplicate suppression",server_reach_out())
    require("QUIC NAT traversal IPv4 socket address mapping",ipv4_probes())
    require("QUIC NAT traversal server advertisements and withdrawals",server_send())
    require("QUIC NAT traversal client probe round generation",client_send())
    require("QUIC NAT traversal sequence rollover",sequence_rollover())
    return Unit{}
