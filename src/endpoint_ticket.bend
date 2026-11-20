import Base
import ./relay_url.bend as Url
import ./ed25519.bend as Ed
import ./endpoint_id.bend as Id
import ./relay.bend as Wire

type TransportAddress is Data:
  Relay{url: List<&2,U32>}
  IPv4{ip: List<&2,U32>, port: U32}
  IPv6{ip: List<&2,U32>, port: U32}
  Custom{hi: U32, lo: U32, data: List<&2,U32>}

type EndpointTicket is Data:
  Ticket{endpoint_id: List<&2,U32>, addresses: List<&2,TransportAddress>}

type Integer is Data:
  Value{hi: U32, lo: U32, tail: List<&2,U32>}
  InvalidInteger{}

def field_lo(+value: U32, shift: U32, +lo: U32, low: Bool) -> U32:
  U32.or(lo,U32.mul(Bool.to_u32(low),U32.shln(value,U32.to_nat(U32.and(shift,31)))))

def field_hi(+value: U32, +shift: U32, high: Bool) -> U32:
  match shift high:
    case 28 _:
      U32.shrn(value,4n)
    case _ True{}:
      U32.shln(value,U32.to_nat(U32.sub(shift,32)))
    case _ _:
      0

def integer(+fuel: Nat, input: List<&2,U32>, +shift: U32, +hi: U32, +lo: U32,
    done: Bool, valid: Bool) -> Integer:
  match fuel input done valid:
    case _ _ True{} True{}:
      Value{hi,lo,input}
    case 1n+left Con{+byte,tail} False{} True{}:
      +value = U32.and(byte,127)
      integer(left,tail,U32.add(shift,7),U32.or(hi,field_hi(value,shift,U32.is_ge(shift,32))),
        field_lo(value,shift,lo,U32.is_lt(shift,32)),U32.is_lt(byte,128),
        U32.is_le(byte,255) && (U32.is_lt(shift,63) || U32.is_le(value,1)))
    case _ _ _ _:
      InvalidInteger{}

def read_integer(input: List<&2,U32>, width: Nat) -> Integer:
  integer(width,input,0,0,0,False{},True{})

def put_integer(fuel: Nat, +hi: U32, +lo: U32, tail: List<&2,U32>, more: Bool) -> List<&2,U32>:
  match fuel more:
    case 1n+left True{}:
      +upper = U32.shrn(hi,7n)
      +lower = U32.or(U32.shln(hi,25n),U32.shrn(lo,7n))
      Con{U32.or(U32.and(lo,127),128),put_integer(left,upper,lower,tail,U32.is_gt(upper,0) || U32.is_ge(lower,128))}
    case _ _:
      Con{lo,tail}

def put(+hi: U32, +lo: U32, tail: List<&2,U32>) -> List<&2,U32>:
  put_integer(9n,hi,lo,tail,U32.is_gt(hi,0) || U32.is_ge(lo,128))

type ReadAddress is Data:
  Address{value: TransportAddress, tail: List<&2,U32>}
  InvalidAddress{}

def parsed_relay(url: Maybe<&2,List<&2,U32>>, tail: List<&2,U32>) -> ReadAddress:
  match url:
    case Some{canonical}:
      Address{Relay{canonical},tail}
    case None{}:
      InvalidAddress{}

def relay_bytes(url: List<&2,U32>, tail: List<&2,U32>, valid: Bool) -> ReadAddress:
  match valid:
    case True{}:
      parsed_relay(Url.normalize(url),tail)
    case False{}:
      InvalidAddress{}

def read_relay(payload: Wire.Split) -> ReadAddress:
  match payload:
    case Wire.Prefix{url,tail}:
      parsed_relay(Url.normalize(url),tail)
    case Wire.ShortPrefix{}:
      InvalidAddress{}

def relay_length(length: Integer) -> ReadAddress:
  match length:
    case Value{0,lo,tail}:
      read_relay(Wire.split_peer(U32.to_nat(lo),tail,[]))
    case _:
      InvalidAddress{}

def port_address(address: TransportAddress, tail: List<&2,U32>, valid: Bool) -> ReadAddress:
  match valid:
    case True{}:
      Address{address,tail}
    case False{}:
      InvalidAddress{}

def read_port(value: Integer, ip: List<&2,U32>, v6: Bool) -> ReadAddress:
  match value v6:
    case Value{0,+port,tail} True{}:
      port_address(IPv6{ip,port},tail,U32.is_le(port,65535))
    case Value{0,+port,tail} False{}:
      port_address(IPv4{ip,port},tail,U32.is_le(port,65535))
    case _ _:
      InvalidAddress{}

def read_ip(parsed: Wire.Split, v6: Bool) -> ReadAddress:
  match parsed:
    case Wire.Prefix{ip,tail}:
      read_port(read_integer(tail,3n),ip,v6)
    case Wire.ShortPrefix{}:
      InvalidAddress{}

def read_socket(kind: Integer) -> ReadAddress:
  match kind:
    case Value{0,0,tail}:
      read_ip(Wire.split_peer(4n,tail,[]),False{})
    case Value{0,1,tail}:
      read_ip(Wire.split_peer(16n,tail,[]),True{})
    case _:
      InvalidAddress{}

def custom_data(parsed: Wire.Split, hi: U32, lo: U32) -> ReadAddress:
  match parsed:
    case Wire.Prefix{data,tail}:
      Address{Custom{hi,lo,data},tail}
    case Wire.ShortPrefix{}:
      InvalidAddress{}

def custom_length(parsed: Integer, hi: U32, lo: U32) -> ReadAddress:
  match parsed:
    case Value{0,length,tail}:
      custom_data(Wire.split_peer(U32.to_nat(length),tail,[]),hi,lo)
    case _:
      InvalidAddress{}

def read_custom(tag: Integer) -> ReadAddress:
  match tag:
    case Value{hi,lo,tail}:
      custom_length(read_integer(tail,10n),hi,lo)
    case InvalidInteger{}:
      InvalidAddress{}

def read_address(kind: Integer) -> ReadAddress:
  match kind:
    case Value{0,0,tail}:
      relay_length(read_integer(tail,10n))
    case Value{0,1,tail}:
      read_socket(read_integer(tail,5n))
    case Value{0,2,tail}:
      read_custom(read_integer(tail,10n))
    case _:
      InvalidAddress{}

def more_addresses(read: ReadAddress, next: List<&2,U32> -> TransportAddress -> Maybe<&2,List<&2,TransportAddress>>)
    -> Maybe<&2,List<&2,TransportAddress>>:
  match read:
    case Address{address,tail}:
      next(tail,address)
    case InvalidAddress{}:
      None{}

def read_addresses(count: Nat, input: List<&2,U32>, reversed: List<&2,TransportAddress>)
    -> Maybe<&2,List<&2,TransportAddress>>:
  match count:
    case 0n:
      Some{List.reverse(&2,TransportAddress,reversed)}
    case 1n+left:
      more_addresses(read_address(read_integer(input,5n)),tail => address => read_addresses(left,tail,Con{address,reversed}))

def bytes_le(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} _:
      True{}
    case Con{+x,xs} Con{+y,ys}:
      U32.is_lt(x,y) || (U32.is_eq(x,y) && bytes_le(xs,ys))
    case _ _:
      False{}

def then_order(equal: Bool, less: Bool, next: Unit -> Bool) -> Bool:
  less || (equal && next(Unit{}))

def ip_le(+a: List<&2,U32>, pa: U32, +b: List<&2,U32>, pb: U32) -> Bool:
  bytes_le(a,b) && (Bool.not(bytes_le(b,a)) || U32.is_le(pa,pb))

def data_le(+a: List<&2,U32>, +b: List<&2,U32>, +an: U32, +bn: U32, inline: Bool) -> Bool:
  match inline:
    case True{}:
      then_order(U32.is_eq(an,bn),U32.is_lt(an,bn),_ => bytes_le(a,b))
    case False{}:
      then_order(U32.is_eq(Bool.to_u32(U32.is_le(an,30)),Bool.to_u32(U32.is_le(bn,30))),
        U32.is_le(an,30) && U32.is_gt(bn,30),_ => bytes_le(a,b))

def measured_data_le(+a: List<&2,U32>, +b: List<&2,U32>) -> Bool:
  +an = U32.from_nat(List.length(&2,U32,a))
  +bn = U32.from_nat(List.length(&2,U32,b))
  data_le(a,b,an,bn,U32.is_le(an,30) && U32.is_le(bn,30))

def custom_le(+ah: U32, +al: U32, +bh: U32, +bl: U32, a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  then_order(U32.is_eq(ah,bh),U32.is_lt(ah,bh),
    _ => then_order(U32.is_eq(al,bl),U32.is_lt(al,bl),_ => measured_data_le(a,b)))

def address_le(a: TransportAddress, b: TransportAddress) -> Bool:
  match a b:
    case Relay{x} Relay{y}:
      bytes_le(x,y)
    case Relay{_} _:
      True{}
    case IPv4{x,p} IPv4{y,q}:
      ip_le(x,p,y,q)
    case IPv4{_,_} IPv6{_,_}:
      True{}
    case IPv6{x,p} IPv6{y,q}:
      ip_le(x,p,y,q)
    case IPv4{_,_} Custom{_,_,_}:
      True{}
    case IPv6{_,_} Custom{_,_,_}:
      True{}
    case Custom{ah,al,x} Custom{bh,bl,y}:
      custom_le(ah,al,bh,bl,x,y)
    case _ _:
      False{}

def keep_distinct(previous: TransportAddress, reversed: List<&2,TransportAddress>, equal: Bool)
    -> List<&2,TransportAddress>:
  match equal:
    case True{}:
      reversed
    case False{}:
      Con{previous,reversed}

def collapse(items: List<&2,TransportAddress>, +previous: TransportAddress, reversed: List<&2,TransportAddress>)
    -> List<&2,TransportAddress>:
  match items:
    case Nil{}:
      List.reverse(&2,TransportAddress,Con{previous,reversed})
    case Con{+current,tail}:
      collapse(tail,current,keep_distinct(previous,reversed,address_le(current,previous)))

def unique(sorted: List<&2,TransportAddress>) -> List<&2,TransportAddress>:
  match sorted:
    case Nil{}:
      []
    case Con{first,rest}:
      collapse(rest,first,[])

def ordered(addresses: List<&2,TransportAddress>) -> List<&2,TransportAddress>:
  unique(List.sort(TransportAddress,address_le,addresses))

def assemble(key: List<&2,U32>, addresses: Maybe<&2,List<&2,TransportAddress>>) -> Maybe<&2,EndpointTicket>:
  match addresses:
    case Some{items}:
      Some{Ticket{key,ordered(items)}}
    case None{}:
      None{}

def read_count(key: List<&2,U32>, count: Integer) -> Maybe<&2,EndpointTicket>:
  match count:
    case Value{0,lo,tail}:
      assemble(key,read_addresses(U32.to_nat(lo),tail,[]))
    case _:
      None{}

def read_key(prefix: Wire.Split) -> Maybe<&2,EndpointTicket>:
  match prefix:
    case Wire.Prefix{key,tail}:
      read_count(key,read_integer(tail,10n))
    case Wire.ShortPrefix{}:
      None{}

def read_version(version: Integer) -> Maybe<&2,EndpointTicket>:
  match version:
    case Value{0,0,rest}:
      read_key(Wire.split_peer(32n,rest,[]))
    case _:
      None{}

def valid_ticket(ticket: EndpointTicket, valid: Bool) -> Maybe<&2,EndpointTicket>:
  match valid:
    case True{}:
      Some{ticket}
    case False{}:
      None{}

def validate(ticket: Maybe<&2,EndpointTicket>) -> IO(Maybe<&2,EndpointTicket>):
  match ticket:
    case Some{Ticket{+key,addresses}}:
      do IO<Maybe<&2,EndpointTicket>>:
        valid : Bool <- Ed.valid_public_key(key)
        return valid_ticket(Ticket{key,addresses},valid)
    case None{}:
      IO.pure(Maybe<&2,EndpointTicket>,None{})

def decode_checked(bytes: List<&2,U32>, measured: Wire.Size) -> IO(Maybe<&2,EndpointTicket>):
  match measured:
    case Wire.Length{_}:
      validate(read_version(read_integer(bytes,5n)))
    case _:
      IO.pure(Maybe<&2,EndpointTicket>,None{})

def decode_bytes(+bytes: List<&2,U32>) -> IO(Maybe<&2,EndpointTicket>):
  decode_checked(bytes,Wire.measure_limited(bytes,4294967295))

def append(a: List<&2,U32>, b: List<&2,U32>) -> List<&2,U32>:
  List.append(&2,U32,a,b)

def put_payload(+payload: List<&2,U32>, tail: List<&2,U32>) -> List<&2,U32>:
  put(0,U32.from_nat(List.length(&2,U32,payload)),append(payload,tail))

def encode_addresses(addresses: List<&2,TransportAddress>) -> List<&2,U32>:
  match addresses:
    case Nil{}:
      []
    case Con{Relay{url},rest}:
      Con{0,put_payload(url,encode_addresses(rest))}
    case Con{IPv4{ip,port},rest}:
      Con{1,Con{0,append(ip,put(0,port,encode_addresses(rest)))}}
    case Con{IPv6{ip,port},rest}:
      Con{1,Con{1,append(ip,put(0,port,encode_addresses(rest)))}}
    case Con{Custom{hi,lo,data},rest}:
      Con{2,put(hi,lo,put_payload(data,encode_addresses(rest)))}

def exact_bytes(size: Wire.Size, n: U32) -> Bool:
  match size:
    case Wire.Length{actual}:
      U32.is_eq(actual,n)
    case _:
      False{}

def byte_values(size: Wire.Size) -> Bool:
  match size:
    case Wire.Length{_}:
      True{}
    case _:
      False{}

def valid_address(address: TransportAddress) -> Bool:
  match address:
    case Relay{url}:
      Maybe.is_some(&2,List<&2,U32>,Url.normalize(url))
    case IPv4{ip,port}:
      exact_bytes(Wire.measure_limited(ip,4),4) && U32.is_le(port,65535)
    case IPv6{ip,port}:
      exact_bytes(Wire.measure_limited(ip,16),16) && U32.is_le(port,65535)
    case Custom{_,_,data}:
      byte_values(Wire.measure_limited(data,4294967295))

def addresses_valid(addresses: List<&2,TransportAddress>) -> Bool:
  match addresses:
    case Nil{}:
      True{}
    case Con{address,rest}:
      valid_address(address) && addresses_valid(rest)

def ticket_bytes(key: List<&2,U32>, +addresses: List<&2,TransportAddress>, valid: Bool) -> Maybe<&2,List<&2,U32>>:
  match valid:
    case True{}:
      Some{Con{0,append(key,put(0,U32.from_nat(List.length(&2,TransportAddress,addresses)),encode_addresses(addresses)))}}
    case False{}:
      None{}

def canonical_address(+address: TransportAddress) -> Maybe<&2,TransportAddress>:
  match address:
    case Relay{url}:
      Maybe.map(&2,List<&2,U32>,TransportAddress,s => Relay{s},Url.normalize(url))
    case _:
      Bool.pick(Maybe<&2,TransportAddress>,valid_address(address),Some{address},None{})

def prepend_address(head: Maybe<&2,TransportAddress>, tail: Maybe<&2,List<&2,TransportAddress>>)
    -> Maybe<&2,List<&2,TransportAddress>>:
  match head tail:
    case Some{h} Some{t}:
      Some{Con{h,t}}
    case _ _:
      None{}

def canonical_addresses(items: List<&2,TransportAddress>) -> Maybe<&2,List<&2,TransportAddress>>:
  match items:
    case Nil{}:
      Some{[]}
    case Con{h,t}:
      prepend_address(canonical_address(h),canonical_addresses(t))

def encode_bytes(ticket: EndpointTicket) -> Maybe<&2,List<&2,U32>>:
  Ticket{+key,addresses} = ticket
  Maybe.bind(&2,List<&2,TransportAddress>,List<&2,U32>,canonical_addresses(addresses),
    sorted => ticket_bytes(key,ordered(sorted),exact_bytes(Wire.measure_limited(key,32),32)))

def base32_char(index: Nat, symbols: List<&2,Char>) -> Char:
  match index symbols:
    case 0n Con{symbol,_}:
      symbol
    case 1n+left Con{_,rest}:
      base32_char(left,rest)
    case _ _:
      Char.from_u32(0)

def symbol(bits: U32) -> Char:
  base32_char(U32.to_nat(bits),String.to_list("abcdefghijklmnopqrstuvwxyz234567"))

def final_symbol(word: U32, bits: U32, output: List<&2,Char>, pending: Bool) -> List<&2,Char>:
  match pending:
    case True{}:
      Con{symbol(U32.shln(word,U32.to_nat(U32.sub(5,bits)))),output}
    case False{}:
      output

def pack32(fuel: Nat, +bytes: List<&2,U32>, +word: U32, +bits: U32, output: List<&2,Char>, ready: Bool) -> List<&2,Char>:
  match fuel bytes ready:
    case 1n+left _ True{}:
      +remaining = U32.sub(bits,5)
      pack32(left,bytes,U32.and(word,Id.low_mask(remaining)),remaining,
        Con{symbol(U32.shrn(word,U32.to_nat(remaining))),output},U32.is_ge(remaining,5))
    case 1n+left Con{byte,tail} False{}:
      pack32(left,tail,U32.or(U32.shln(word,8n),byte),U32.add(bits,8),output,True{})
    case _ _ _:
      final_symbol(word,bits,output,U32.is_gt(bits,0))

def base32_text(encoded: Maybe<&2,List<&2,U32>>) -> Maybe<&2,String>:
  match encoded:
    case Some{+bytes}:
      +size = List.length(&2,U32,bytes)
      Some{String.append("endpoint",String.from_list(List.reverse(&2,Char,pack32(Nat.mul(size,3n),bytes,0,0,[],False{}))))}
    case None{}:
      None{}

def encode(ticket: EndpointTicket) -> Maybe<&2,String>:
  base32_text(encode_bytes(ticket))

def decoded32(payload: Maybe<&2,List<&2,U32>>) -> IO(Maybe<&2,EndpointTicket>):
  match payload:
    case Some{bytes}:
      decode_bytes(bytes)
    case None{}:
      IO.pure(Maybe<&2,EndpointTicket>,None{})

def unpack32(symbols: Maybe<&2,List<&2,U32>>, +length: Nat, valid: Bool) -> IO(Maybe<&2,EndpointTicket>):
  match symbols valid:
    case Some{digits} True{}:
      decoded32(Id.unpack(Nat.mul(length,2n),digits,5,0,0,[],False{}))
    case _ _:
      IO.pure(Maybe<&2,EndpointTicket>,None{})

def decode_text(+text: String, +length: Nat) -> IO(Maybe<&2,EndpointTicket>):
  +bits = U32.mul(U32.from_nat(length),5)
  unpack32(Id.read_digits(String.to_list(text),True{}),length,U32.is_lt(U32.and(bits,7),5))

def decode_prefixed(text: String, good: Bool) -> IO(Maybe<&2,EndpointTicket>):
  match good:
    case True{}:
      +payload = String.drop(text,8n)
      decode_text(payload,String.length(payload))
    case False{}:
      IO.pure(Maybe<&2,EndpointTicket>,None{})

def decode(+text: String) -> IO(Maybe<&2,EndpointTicket>):
  decode_prefixed(text,String.starts_with(text,"endpoint"))
