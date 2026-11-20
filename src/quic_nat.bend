import Base

# Wire format used by noq-proto 1.5.0. These are QUIC frames, not
# application datagrams. A transport must negotiate the extension first.
type VarInt is Data:
  Var{high: U32, low: U32}

type Address is Data:
  IPv4{bytes: List<&2,U32>}
  IPv6{bytes: List<&2,U32>}

type Frame is Data:
  AddAddress{sequence: VarInt, address: Address, port: U32}
  ReachOut{round: VarInt, address: Address, port: U32}
  RemoveAddress{sequence: VarInt}

type IntegerInput is Data:
  Integer{value: VarInt, width: U32, rest: List<&2,U32>}
  ShortInteger{}
  InvalidInteger{}

def integer_byte(+high: U32, +low: U32, +byte: U32, valid: Bool,
    next: U32 -> U32 -> IntegerInput) -> IntegerInput:
  match valid:
    case True{}:
      next(U32.or(U32.shln(high,8n),U32.shrn(low,24n)),U32.or(U32.shln(low,8n),byte))
    case False{}:
      InvalidInteger{}

def read_integer(bytes: List<&2,U32>, count: Nat, +width: U32, +high: U32, +low: U32) -> IntegerInput:
  match bytes count:
    case rest 0n:
      Integer{Var{high,low},width,rest}
    case Nil{} 1n+left:
      ShortInteger{}
    case Con{+byte,rest} 1n+left:
      integer_byte(high,low,byte,U32.is_le(byte,255),hi => lo => read_integer(rest,left,width,hi,lo))

def start_integer(tail: List<&2,U32>, head: U32, prefix: U32, valid: Bool) -> IntegerInput:
  match prefix valid:
    case _ False{}:
      InvalidInteger{}
    case 0 True{}:
      Integer{Var{0,U32.and(head,63)},1,tail}
    case 1 True{}:
      read_integer(tail,1n,2,0,U32.and(head,63))
    case 2 True{}:
      read_integer(tail,3n,4,0,U32.and(head,63))
    case _ True{}:
      read_integer(tail,7n,8,0,U32.and(head,63))

def split_integer(bytes: List<&2,U32>) -> IntegerInput:
  match bytes:
    case Nil{}:
      ShortInteger{}
    case Con{+head,tail}:
      start_integer(tail,head,U32.shrn(head,6n),U32.is_le(head,255))

def byte_at(value: U32, shift: Nat) -> U32:
  U32.and(U32.shrn(value,shift),255)

def append_word(+value: U32, tail: List<&2,U32>) -> List<&2,U32>:
  Con{byte_at(value,24n),Con{byte_at(value,16n),Con{byte_at(value,8n),Con{byte_at(value,0n),tail}}}}

def small_width(one: Bool, two: Bool) -> U32:
  match one two:
    case True{} _:
      1
    case False{} True{}:
      2
    case False{} False{}:
      4

def integer_width(+low: U32, narrow: Bool) -> U32:
  match narrow:
    case True{}:
      small_width(U32.is_le(low,63),U32.is_le(low,16383))
    case False{}:
      8

def write_integer(high: U32, +low: U32, width: U32, tail: List<&2,U32>) -> List<&2,U32>:
  match width:
    case 1:
      Con{low,tail}
    case 2:
      Con{U32.or(byte_at(low,8n),64),Con{byte_at(low,0n),tail}}
    case 4:
      append_word(U32.or(low,2147483648),tail)
    case _:
      append_word(U32.or(high,3221225472),append_word(low,tail))

def integer_bytes(+high: U32, +low: U32, tail: List<&2,U32>) -> List<&2,U32>:
  write_integer(high,low,integer_width(low,U32.is_eq(high,0) && U32.is_lt(low,1073741824)),tail)

def fits_integer(value: VarInt) -> Bool:
  Var{high,_} = value
  U32.is_lt(high,1073741824)

type DecodeResult is Data:
  Decoded{frame: Frame, rest: List<&2,U32>}
  ShortFrame{}
  InvalidFrame{}
  OtherFrame{}

def address_frame(kind: U32, seq: VarInt, ip: Address, port: U32, tail: List<&2,U32>) -> DecodeResult:
  match kind:
    case 0:
      Decoded{AddAddress{seq,ip,port},tail}
    case _:
      Decoded{ReachOut{seq,ip,port},tail}

def address_of(bytes: List<&2,U32>, family: U32) -> Address:
  match family:
    case 4:
      IPv4{bytes}
    case _:
      IPv6{bytes}

def checked_port(seq: VarInt, ip: Address, kind: U32, port: U32, tail: List<&2,U32>, valid: Bool) -> DecodeResult:
  match valid:
    case True{}:
      address_frame(kind,seq,ip,port,tail)
    case False{}:
      InvalidFrame{}

def finish_address(port_bytes: List<&2,U32>, seq: VarInt, ip: Address, kind: U32) -> DecodeResult:
  match port_bytes:
    case Con{+hi,Con{+lo,tail}}:
      checked_port(seq,ip,kind,U32.or(U32.shln(hi,8n),lo),tail,U32.is_le(hi,255) && U32.is_le(lo,255))
    case _:
      ShortFrame{}

def read_address(count: Nat, bytes: List<&2,U32>, reversed: List<&2,U32>, seq: VarInt, +family: U32, kind: U32,
    valid: Bool) -> DecodeResult:
  match count bytes valid:
    case _ _ False{}:
      InvalidFrame{}
    case 0n port True{}:
      finish_address(port,seq,address_of(List.reverse(&2,U32,reversed),family),kind)
    case 1n+left Con{+byte,tail} True{}:
      read_address(left,tail,Con{byte,reversed},seq,family,kind,U32.is_le(byte,255))
    case 1n+left Nil{} True{}:
      ShortFrame{}

def read_body(incoming: IntegerInput, kind: U32) -> DecodeResult:
  match incoming kind:
    case Integer{seq,_,tail} 4:
      Decoded{RemoveAddress{seq},tail}
    case Integer{seq,_,tail} 0:
      read_address(4n,tail,[],seq,4,0,True{})
    case Integer{seq,_,tail} 1:
      read_address(16n,tail,[],seq,6,0,True{})
    case Integer{seq,_,tail} 2:
      read_address(4n,tail,[],seq,4,1,True{})
    case Integer{seq,_,tail} 3:
      read_address(16n,tail,[],seq,6,1,True{})
    case InvalidInteger{} _:
      InvalidFrame{}
    case ShortInteger{} _:
      ShortFrame{}
    case _ _:
      OtherFrame{}

# QUIC requires the shortest encoding for frame types.
def read_type(tag: U32, width: U32, body: List<&2,U32>, known: Bool) -> DecodeResult:
  match width known:
    case 4 True{}:
      read_body(split_integer(body),U32.sub(tag,4030352))
    case _ True{}:
      InvalidFrame{}
    case _ False{}:
      OtherFrame{}

def typed_frame(header: IntegerInput) -> DecodeResult:
  match header:
    case Integer{Var{0,+tag},width,body}:
      read_type(tag,width,body,U32.is_ge(tag,4030352) && U32.is_le(tag,4030356))
    case Integer{_,_,_}:
      OtherFrame{}
    case ShortInteger{}:
      ShortFrame{}
    case InvalidInteger{}:
      InvalidFrame{}

def decode(bytes: List<&2,U32>) -> DecodeResult:
  typed_frame(split_integer(bytes))

def valid_address(bytes: List<&2,U32>, width: Nat, valid: Bool) -> Bool:
  match bytes width valid:
    case Nil{} 0n True{}:
      True{}
    case Con{byte,tail} 1n+left True{}:
      valid_address(tail,left,U32.is_le(byte,255))
    case _ _ _:
      False{}

def encode_packet(tag: U32, seq: VarInt, body: List<&2,U32>, valid: Bool) -> Maybe<&2,List<&2,U32>>:
  match seq valid:
    case Var{high,low} True{}:
      Some{integer_bytes(0,tag,integer_bytes(high,low,body))}
    case _ False{}:
      None{}

def encode_address(+tag: U32, +seq: VarInt, +bytes: List<&2,U32>, +port: U32, width: Nat) -> Maybe<&2,List<&2,U32>>:
  encode_packet(tag,seq,List.append(&2,U32,bytes,[byte_at(port,8n),byte_at(port,0n)]),
    valid_address(bytes,width,True{}) && U32.is_le(port,65535) && fits_integer(seq))

def encode(frame: Frame) -> Maybe<&2,List<&2,U32>>:
  match frame:
    case AddAddress{seq,IPv4{bytes},port}:
      encode_address(4030352,seq,bytes,port,4n)
    case AddAddress{seq,IPv6{bytes},port}:
      encode_address(4030353,seq,bytes,port,16n)
    case ReachOut{seq,IPv4{bytes},port}:
      encode_address(4030354,seq,bytes,port,4n)
    case ReachOut{seq,IPv6{bytes},port}:
      encode_address(4030355,seq,bytes,port,16n)
    case RemoveAddress{+seq}:
      encode_packet(4030356,seq,[],fits_integer(seq))

# noq 1.5.0 uses one nonzero byte for the limit payload.
def limit_value(limit: U32, legal: Bool) -> Maybe<&2,U32>:
  match legal:
    case True{}:
      Some{limit}
    case False{}:
      None{}

def decode_limit(payload: List<&2,U32>) -> Maybe<&2,U32>:
  match payload:
    case [+limit]:
      limit_value(limit,U32.is_gt(limit,0) && U32.is_le(limit,255))
    case _:
      None{}

def encode_parameter(+limit: U32, valid: Bool) -> Maybe<&2,List<&2,U32>>:
  match valid:
    case True{}:
      Some{[192,0,61,127,145,18,4,1,1,limit]}
    case False{}:
      None{}

def encode_limit(+limit: U32) -> Maybe<&2,List<&2,U32>>:
  encode_parameter(limit,U32.is_gt(limit,0) && U32.is_le(limit,255))

type ParameterResult is Data:
  ParameterAbsent{}
  ParameterLimit{limit: U32}
  ParameterMalformed{}

type ParameterTail is Data:
  ParameterRest{rest: List<&2,U32>}
  ParameterTruncated{}

def skip_parameter(length: Nat, bytes: List<&2,U32>) -> ParameterTail:
  match length bytes:
    case 0n rest:
      ParameterRest{rest}
    case 1n+left Con{_,tail}:
      skip_parameter(left,tail)
    case _ _:
      ParameterTruncated{}

def known_parameter(+value: U32, rest: List<&2,U32>, previous: ParameterResult, valid: Bool,
    next: List<&2,U32> -> ParameterResult -> ParameterResult) -> ParameterResult:
  match previous valid:
    case ParameterAbsent{} True{}:
      next(rest,ParameterLimit{value})
    case _ _:
      ParameterMalformed{}

def unknown_parameter(tail: ParameterTail, previous: ParameterResult,
    next: List<&2,U32> -> ParameterResult -> ParameterResult) -> ParameterResult:
  match tail:
    case ParameterRest{rest}:
      next(rest,previous)
    case ParameterTruncated{}:
      ParameterMalformed{}

def parameter_body(header: IntegerInput, known: Bool, previous: ParameterResult,
    next: List<&2,U32> -> ParameterResult -> ParameterResult) -> ParameterResult:
  match header known:
    case Integer{Var{0,1},_,Con{+byte,rest}} True{}:
      known_parameter(byte,rest,previous,U32.is_gt(byte,0) && U32.is_le(byte,255),next)
    case Integer{Var{0,size},_,rest} False{}:
      unknown_parameter(skip_parameter(U32.to_nat(size),rest),previous,next)
    case _ _:
      ParameterMalformed{}

def parameter_header(header: IntegerInput, previous: ParameterResult,
    next: List<&2,U32> -> ParameterResult -> ParameterResult) -> ParameterResult:
  match header:
    case Integer{Var{15743,2433876993},_,rest}:
      parameter_body(split_integer(rest),True{},previous,next)
    case Integer{_,_,rest}:
      parameter_body(split_integer(rest),False{},previous,next)
    case _:
      ParameterMalformed{}

def scan_parameters(fuel: Nat, parameters: List<&2,U32>, result: ParameterResult) -> ParameterResult:
  match fuel parameters:
    case _ Nil{}:
      result
    case 1n+left payload:
      parameter_header(split_integer(payload),result,rest => seen => scan_parameters(left,rest,seen))
    case _ _:
      ParameterMalformed{}

# Walk an entire QUIC Transport Parameters extension to find the n0 limit.
# Duplicate n0 parameters are malformed even when their values agree.
def read_parameters(+parameters: List<&2,U32>) -> ParameterResult:
  scan_parameters(List.length(&2,U32,parameters),parameters,ParameterAbsent{})
