import Base
import ./quic_nat.bend as Wire
import ./quic_nat_state.bend as Peer

type LocalState is Data:
  Disabled{}
  Client{limit: U32, round: Wire.VarInt, candidates: List<&2,Peer.Candidate>}
  Server{limit: U32, next_id: Wire.VarInt, advertised: List<&2,Peer.Advertisement>}

type LocalEvent is Data:
  Unchanged{}
  Updated{}
  Send{frame: Wire.Frame}
  AddressLimit{}
  InvalidAddress{}
  NotNegotiated{}

type Change is Data:
  Changed{state: LocalState, event: LocalEvent}

type RoundEvent is Data:
  RoundStarted{round: Wire.VarInt, frames: List<&2,Wire.Frame>, targets: List<&2,Peer.Candidate>}
  NoLocalCandidates{}
  CannotStartRound{}

type RoundResult is Data:
  Round{state: LocalState, event: RoundEvent}

# The peer's receive limit bounds this endpoint's local candidates.
def start(role: Peer.Role, multipath: Bool, local: Maybe<&2,U32>, remote: Maybe<&2,U32>) -> LocalState:
  match role multipath local remote:
    case Peer.Client{} True{} Some{_} Some{limit}:
      Client{limit,Wire.Var{0,0},[]}
    case Peer.Server{_} True{} Some{_} Some{limit}:
      Server{limit,Wire.Var{0,0},[]}
    case _ _ _ _:
      Disabled{}

def increment(+hi: U32, +lo: U32) -> Wire.VarInt:
  match hi lo:
    case 1073741823 4294967295:
      Wire.Var{1073741823,4294967295}
    case h 4294967295:
      Wire.Var{U32.add(h,1),0}
    case h l:
      Wire.Var{h,U32.add(l,1)}

def next(value: Wire.VarInt) -> Wire.VarInt:
  Wire.Var{hi,lo} = value
  increment(hi,lo)

def canonical_socket(input: Peer.Candidate) -> Peer.Candidate:
  Peer.Socket{ip,port} = input
  Peer.Socket{Peer.canonical(ip),port}

def id_if_equal(id: Wire.VarInt, same: Bool, search: Unit -> Maybe<&2,Wire.VarInt>) -> Maybe<&2,Wire.VarInt>:
  match same:
    case True{}:
      Some{id}
    case False{}:
      search(Unit{})

def find_advertised(+address: Peer.Candidate, entries: List<&2,Peer.Advertisement>) -> Maybe<&2,Wire.VarInt>:
  match entries:
    case Nil{}:
      None{}
    case Con{Peer.Advertised{id,existing},rest}:
      id_if_equal(id,Peer.equal_socket(address,existing),_ => find_advertised(address,rest))

def add_client(+limit: U32, round: Wire.VarInt, candidates: List<&2,Peer.Candidate>,
    address: Peer.Candidate, exists: Bool, room: Bool) -> Change:
  match exists room:
    case True{} _:
      Changed{Client{limit,round,candidates},Unchanged{}}
    case False{} True{}:
      Changed{Client{limit,round,Con{address,candidates}},Updated{}}
    case False{} False{}:
      Changed{Client{limit,round,candidates},AddressLimit{}}

def advertise(+limit: U32, +id: Wire.VarInt, entries: List<&2,Peer.Advertisement>, address: Peer.Candidate,
    existing: Maybe<&2,Wire.VarInt>, room: Bool) -> Change:
  match address existing room:
    case _ Some{_} _:
      Changed{Server{limit,id,entries},Unchanged{}}
    case Peer.Socket{+ip,+port} None{} True{}:
      Changed{Server{limit,next(id),Con{Peer.Advertised{id,Peer.Socket{ip,port}},entries}},
        Send{Wire.AddAddress{id,ip,port}}}
    case _ None{} False{}:
      Changed{Server{limit,id,entries},AddressLimit{}}

def add_canonical(state: LocalState, +address: Peer.Candidate) -> Change:
  match state:
    case Client{+limit,round,+entries}:
      add_client(limit,round,entries,address,Peer.contains(address,entries),
        Nat.is_lt(List.length(&2,Peer.Candidate,entries),U32.to_nat(limit)))
    case Server{+limit,id,+entries}:
      advertise(limit,id,entries,address,find_advertised(address,entries),
        Nat.is_lt(List.length(&2,Peer.Advertisement,entries),U32.to_nat(limit)))
    case Disabled{}:
      Changed{Disabled{},NotNegotiated{}}

def valid_ip(ip: Wire.Address) -> Bool:
  match ip:
    case Wire.IPv4{bytes}:
      Wire.valid_address(bytes,4n,True{})
    case Wire.IPv6{bytes}:
      Wire.valid_address(bytes,16n,True{})

def valid_candidate(candidate: Peer.Candidate) -> Bool:
  Peer.Socket{ip,port} = candidate
  U32.is_le(port,65535) && valid_ip(ip)

def add_checked(state: LocalState, address: Peer.Candidate, valid: Bool) -> Change:
  match state valid:
    case Disabled{} _:
      Changed{Disabled{},NotNegotiated{}}
    case unchanged False{}:
      Changed{unchanged,InvalidAddress{}}
    case active True{}:
      add_canonical(active,canonical_socket(address))

def add(state: LocalState, +address: Peer.Candidate) -> Change:
  add_checked(state,address,valid_candidate(address))

def keep_candidate(item: Peer.Candidate, remaining: List<&2,Peer.Candidate>, removed: Bool) -> List<&2,Peer.Candidate>:
  match removed:
    case True{}:
      remaining
    case False{}:
      Con{item,remaining}

def without_candidate(+address: Peer.Candidate, entries: List<&2,Peer.Candidate>) -> List<&2,Peer.Candidate>:
  match entries:
    case Nil{}:
      []
    case Con{+item,rest}:
      keep_candidate(item,without_candidate(address,rest),Peer.equal_socket(address,item))

def remove_client(limit: U32, round: Wire.VarInt, entries: List<&2,Peer.Candidate>,
    address: Peer.Candidate, exists: Bool) -> Change:
  match exists:
    case True{}:
      Changed{Client{limit,round,without_candidate(address,entries)},Updated{}}
    case False{}:
      Changed{Client{limit,round,entries},Unchanged{}}

def removed_advertisement(limit: U32, next_id: Wire.VarInt, id: Wire.VarInt, found: Peer.Found) -> Change:
  Peer.Lookup{_,remaining} = found
  Changed{Server{limit,next_id,remaining},Send{Wire.RemoveAddress{id}}}

def withdraw(limit: U32, next_id: Wire.VarInt, entries: List<&2,Peer.Advertisement>,
    found: Maybe<&2,Wire.VarInt>) -> Change:
  match found:
    case None{}:
      Changed{Server{limit,next_id,entries},Unchanged{}}
    case Some{+id}:
      removed_advertisement(limit,next_id,id,Peer.locate(id,entries))

def remove_canonical(state: LocalState, +address: Peer.Candidate) -> Change:
  match state:
    case Client{limit,round,+entries}:
      remove_client(limit,round,entries,address,Peer.contains(address,entries))
    case Server{limit,id,+entries}:
      withdraw(limit,id,entries,find_advertised(address,entries))
    case Disabled{}:
      Changed{Disabled{},NotNegotiated{}}

def remove(state: LocalState, address: Peer.Candidate) -> Change:
  remove_canonical(state,canonical_socket(address))

def reach_frames(+round: Wire.VarInt, entries: List<&2,Peer.Candidate>) -> List<&2,Wire.Frame>:
  match entries:
    case Nil{}:
      []
    case Con{Peer.Socket{ip,port},tail}:
      Con{Wire.ReachOut{round,ip,port},reach_frames(round,tail)}

def insert_target(+target: Peer.Candidate, +tail: List<&2,Peer.Candidate>, already: Bool) -> List<&2,Peer.Candidate>:
  match already:
    case True{}:
      tail
    case False{}:
      Con{target,tail}

def probe_target(mapped: Maybe<&2,Wire.Address>, port: U32,
    +tail: List<&2,Peer.Candidate>) -> List<&2,Peer.Candidate>:
  match mapped:
    case Some{ip}:
      +target = {Peer.Socket{ip,port} : Peer.Candidate}
      insert_target(target,tail,Peer.contains(target,tail))
    case None{}:
      tail

def probe_targets(+ipv6: Bool, entries: List<&2,Peer.Advertisement>) -> List<&2,Peer.Candidate>:
  match entries:
    case Nil{}:
      []
    case Con{Peer.Advertised{_,Peer.Socket{ip,port}},rest}:
      probe_target(Peer.for_socket(ip,ipv6),port,probe_targets(ipv6,rest))

def begin(state: LocalState, inbound: Peer.PeerState, ipv6: Bool) -> RoundResult:
  match state inbound:
    case Client{limit,round,Nil{}} Peer.ClientState{_,_}:
      Round{Client{limit,round,[]},NoLocalCandidates{}}
    case Client{limit,round,+addresses} Peer.ClientState{_,remote}:
      +id = next(round)
      Round{Client{limit,id,addresses},RoundStarted{id,reach_frames(id,addresses),probe_targets(ipv6,remote)}}
    case unchanged _:
      Round{unchanged,CannotStartRound{}}
