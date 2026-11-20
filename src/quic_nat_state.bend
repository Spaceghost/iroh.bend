import Base
import ./quic_nat.bend as Wire

type Role is Data:
  Client{}
  Server{ipv6_socket: Bool}

type Candidate is Data:
  Socket{ip: Wire.Address, port: U32}

type Advertisement is Data:
  Advertised{sequence: Wire.VarInt, address: Candidate}

type PeerState is Data:
  Disabled{}
  ClientState{remote_limit: U32, addresses: List<&2,Advertisement>}
  ServerState{remote_limit: U32, ipv6_socket: Bool, round: Wire.VarInt, targets: List<&2,Candidate>}

type PeerEvent is Data:
  Ignored{}
  AddressAdded{address: Candidate}
  AddressRemoved{address: Candidate}
  Probe{round: Wire.VarInt, target: Candidate, restart: Bool}
  ProtocolViolation{}

type Transition is Data:
  Received{state: PeerState, event: PeerEvent}

# The limits come from Wire.decode_limit. Both peers must also negotiate multipath.
def start(role: Role, multipath: Bool, local: Maybe<&2,U32>, remote: Maybe<&2,U32>) -> PeerState:
  match role multipath local remote:
    case Client{} True{} Some{limit} Some{_}:
      ClientState{limit,[]}
    case Server{ipv6} True{} Some{limit} Some{_}:
      ServerState{limit,ipv6,Wire.Var{0,0},[]}
    case _ _ _ _:
      Disabled{}

def equal_bytes(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(x,y) && equal_bytes(xs,ys)
    case _ _:
      False{}

def equal_ip(a: Wire.Address, b: Wire.Address) -> Bool:
  match a b:
    case Wire.IPv4{x} Wire.IPv4{y}:
      equal_bytes(x,y)
    case Wire.IPv6{x} Wire.IPv6{y}:
      equal_bytes(x,y)
    case _ _:
      False{}

def equal_socket(a: Candidate, b: Candidate) -> Bool:
  Socket{ip,port} = a
  Socket{other_ip,other_port} = b
  U32.is_eq(port,other_port) && equal_ip(ip,other_ip)

def equal_sequence(a: Wire.VarInt, b: Wire.VarInt) -> Bool:
  Wire.Var{hi,lo} = a
  Wire.Var{other_hi,other_lo} = b
  U32.is_eq(hi,other_hi) && U32.is_eq(lo,other_lo)

def older(a: Wire.VarInt, b: Wire.VarInt) -> Bool:
  Wire.Var{+hi,lo} = a
  Wire.Var{+other_hi,other_lo} = b
  U32.is_lt(hi,other_hi) || (U32.is_eq(hi,other_hi) && U32.is_lt(lo,other_lo))

def canonical(ip: Wire.Address) -> Wire.Address:
  match ip:
    case Wire.IPv6{[0,0,0,0,0,0,0,0,0,0,255,255,a,b,c,d]}:
      Wire.IPv4{[a,b,c,d]}
    case other:
      other

def for_socket(ip: Wire.Address, ipv6: Bool) -> Maybe<&2,Wire.Address>:
  match ip ipv6:
    case Wire.IPv4{[a,b,c,d]} True{}:
      Some{Wire.IPv6{[0,0,0,0,0,0,0,0,0,0,255,255,a,b,c,d]}}
    case Wire.IPv4{bytes} False{}:
      Some{Wire.IPv4{bytes}}
    case Wire.IPv6{bytes} True{}:
      Some{Wire.IPv6{bytes}}
    case _ _:
      None{}

# Pick out the previous advertisement and preserve the rest of the set.
type Found is Data:
  Lookup{address: Maybe<&2,Candidate>, rest: List<&2,Advertisement>}

def locate_step(entry: Advertisement, found: Found) -> Found:
  Lookup{previous,rest} = found
  Lookup{previous,Con{entry,rest}}

def locate_entry(+entry: Advertisement, +tail: List<&2,Advertisement>, same: Bool, next: Unit -> Found) -> Found:
  match entry same:
    case Advertised{_,address} True{}:
      Lookup{Some{address},tail}
    case kept False{}:
      locate_step(kept,next(Unit{}))

def locate(+seq: Wire.VarInt, addresses: List<&2,Advertisement>) -> Found:
  match addresses:
    case Nil{}:
      Lookup{None{},[]}
    case Con{Advertised{+id,address},+tail}:
      locate_entry(Advertised{id,address},tail,equal_sequence(seq,id),_ => locate(seq,tail))

def add_known(+limit: U32, +seq: Wire.VarInt, +target: Candidate, +rest: List<&2,Advertisement>,
    same: Bool) -> Transition:
  match same:
    case True{}:
      Received{ClientState{limit,Con{Advertised{seq,target},rest}},Ignored{}}
    case False{}:
      Received{ClientState{limit,Con{Advertised{seq,target},rest}},AddressAdded{target}}

def add_new(+limit: U32, +seq: Wire.VarInt, +target: Candidate, +rest: List<&2,Advertisement>,
    room: Bool) -> Transition:
  match room:
    case True{}:
      add_known(limit,seq,target,rest,False{})
    case False{}:
      Received{ClientState{limit,rest},Ignored{}}

def add_remote(+limit: U32, +seq: Wire.VarInt, +target: Candidate, result: Found) -> Transition:
  match result:
    case Lookup{Some{old},rest}:
      add_known(limit,seq,target,rest,equal_socket(target,old))
    case Lookup{None{},+rest}:
      add_new(limit,seq,target,rest,Nat.is_lt(List.length(&2,Advertisement,rest),U32.to_nat(limit)))

def remove_remote(limit: U32, result: Found) -> Transition:
  match result:
    case Lookup{Some{old},rest}:
      Received{ClientState{limit,rest},AddressRemoved{old}}
    case Lookup{None{},rest}:
      Received{ClientState{limit,rest},Ignored{}}

def contains(+target: Candidate, entries: List<&2,Candidate>) -> Bool:
  match entries:
    case Nil{}:
      False{}
    case Con{address,rest}:
      equal_socket(target,address) || contains(target,rest)

def accepted_probe(limit: U32, ipv6: Bool, +round: Wire.VarInt, targets: List<&2,Candidate>,
    +target: Candidate, restart: Bool) -> Transition:
  Received{ServerState{limit,ipv6,round,Con{target,targets}},Probe{round,target,restart}}

def same_round(+limit: U32, ipv6: Bool, round: Wire.VarInt, +targets: List<&2,Candidate>,
    target: Candidate, duplicate: Bool, room: Bool) -> Transition:
  match duplicate room:
    case True{} _:
      Received{ServerState{limit,ipv6,round,targets},Ignored{}}
    case False{} True{}:
      accepted_probe(limit,ipv6,round,targets,target,False{})
    case False{} False{}:
      Received{ServerState{limit,ipv6,round,targets},ProtocolViolation{}}

def valid_probe(+limit: U32, ipv6: Bool, current: Wire.VarInt, +targets: List<&2,Candidate>,
    round: Wire.VarInt, +target: Candidate, restart: Bool) -> Transition:
  match restart:
    case True{}:
      accepted_probe(limit,ipv6,round,[],target,True{})
    case False{}:
      same_round(limit,ipv6,current,targets,target,contains(target,targets),
        Nat.is_lt(List.length(&2,Candidate,targets),U32.to_nat(limit)))

def reach_out(+limit: U32, +ipv6: Bool, +current: Wire.VarInt, +targets: List<&2,Candidate>,
    +round: Wire.VarInt, port: U32, mapped: Maybe<&2,Wire.Address>, stale: Bool) -> Transition:
  match mapped stale:
    case Some{ip} False{}:
      +target = {Socket{ip,port} : Candidate}
      valid_probe(limit,ipv6,current,targets,round,target,older(current,round))
    case _ _:
      Received{ServerState{limit,ipv6,current,targets},Ignored{}}

# Call only for a decoded extension frame on an authenticated 1-RTT connection.
def receive(state: PeerState, frame: Wire.Frame) -> Transition:
  match state frame:
    case ClientState{limit,addresses} Wire.AddAddress{+id,ip,port}:
      add_remote(limit,id,Socket{canonical(ip),port},locate(id,addresses))
    case ClientState{limit,addresses} Wire.RemoveAddress{id}:
      remove_remote(limit,locate(id,addresses))
    case ServerState{limit,+ipv6,+current,targets} Wire.ReachOut{+round,ip,port}:
      reach_out(limit,ipv6,current,targets,round,port,for_socket(canonical(ip),ipv6),older(round,current))
    case rejected _:
      Received{rejected,ProtocolViolation{}}
