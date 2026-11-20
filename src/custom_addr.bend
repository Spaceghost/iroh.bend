import Base
import ./endpoint_ticket.bend as Ticket
import ./endpoint_id.bend as Hex
import ./url_text.bend as Text
import ./relay.bend as Wire
import ./relay_challenge.bend as LE

# The value is the same Custom variant used in EndpointTicket.addresses.
type ParseError is Data:
  MissingSeparator{}
  InvalidId{}
  InvalidData{}

type IdWords is Data:
  Words{hi: U32, lo: U32}

def id_digits(text: String, +hi: U32, +lo: U32, valid: Bool) -> Maybe<&2,IdWords>:
  match text valid:
    case _ False{}:
      None{}
    case SNil{} True{}:
      Some{Words{hi,lo}}
    case SCon{c,rest} True{}:
      +digit = Text.hex_value(Char.to_u32(c))
      id_digits(rest,U32.or(U32.shln(hi,4n),U32.shrn(lo,28n)),U32.or(U32.shln(lo,4n),digit),
        U32.is_le(hi,268435455) && U32.is_lt(digit,16))

def unsigned_id(+text: String) -> Maybe<&2,IdWords>:
  match text:
    case SNil{}:
      None{}
    case SCon{_,_}:
      id_digits(text,0,0,True{})

def parse_id(+text: String) -> Maybe<&2,IdWords>:
  match text:
    case SCon{'+',rest}:
      unsigned_id(rest)
    case _:
      unsigned_id(text)

def lower_hex(c: Char) -> U32:
  +code = Char.to_u32(c)
  Bool.pick(U32,Text.between(code,65,70),16,Text.hex_value(code))

def parse_data(text: String, hi: U32, lo: U32, reversed: List<&2,U32>, valid: Bool)
    -> Result<&2,&2,ParseError,Ticket.TransportAddress>:
  match text valid:
    case SNil{} True{}:
      Done{Ticket.Custom{hi,lo,List.reverse(&2,U32,reversed)}}
    case SCon{a,SCon{b,rest}} True{}:
      +upper = lower_hex(a)
      +lower = lower_hex(b)
      parse_data(rest,hi,lo,Con{U32.or(U32.shln(upper,4n),lower),reversed},U32.is_lt(U32.or(upper,lower),16))
    case _ _:
      Fail{InvalidData{}}

def address_data(id: Maybe<&2,IdWords>, data: String) -> Result<&2,&2,ParseError,Ticket.TransportAddress>:
  match id:
    case Some{Words{hi,lo}}:
      parse_data(data,hi,lo,[],True{})
    case None{}:
      Fail{InvalidId{}}

def parse_parts(parts: Text.Split) -> Result<&2,&2,ParseError,Ticket.TransportAddress>:
  match parts:
    case Text.Split{id,SCon{'_',data}}:
      address_data(parse_id(id),data)
    case _:
      Fail{MissingSeparator{}}

# Iroh accepts upper- or lowercase hex digits in the ID and lowercase hex in the payload.
def parse(text: String) -> Result<&2,&2,ParseError,Ticket.TransportAddress>:
  parse_parts(Text.split(n => U32.is_eq(n,95),text))

def id_text(left: Nat, +hi: U32, +lo: U32, tail: String, more: Bool) -> String:
  match left more:
    case 1n+rest True{}:
      id_text(rest,U32.shrn(hi,4n),U32.or(U32.shln(hi,28n),U32.shrn(lo,4n)),
        SCon{Hex.hex_char(U32.and(lo,15)),tail},U32.is_gt(hi,0) || U32.is_gt(lo,15))
    case _ _:
      tail

def format(addr: Ticket.TransportAddress) -> Maybe<&2,String>:
  match addr:
    case Ticket.Custom{hi,lo,+data}:
      hex = Hex.hex_text(Hex.hex_bytes(data,List.length(&2,U32,data)))
      Maybe.map(&2,String,String,s => id_text(16n,hi,lo,SCon{'_',s},True{}),hex)
    case _:
      None{}

def are_bytes(data: List<&2,U32>) -> Bool:
  List.all(&2,U32,b => U32.is_le(b,255),data)

def binary_parts(prefix: Wire.Split, valid: Bool) -> Result<&2,&2,String,Ticket.TransportAddress>:
  match prefix valid:
    case Wire.ShortPrefix{} _:
      Fail{"data too short"}
    case Wire.Prefix{[a,b,c,d,e,f,g,h],data} True{}:
      Done{Ticket.Custom{LE.le_word(e,f,g,h),LE.le_word(a,b,c,d),data}}
    case _ _:
      Fail{"expected bytes"}

# CustomAddr's raw encoding starts with the full eight-byte little-endian ID.
def from_bytes(+bytes: List<&2,U32>) -> Result<&2,&2,String,Ticket.TransportAddress>:
  binary_parts(Wire.split_peer(8n,bytes,[]),are_bytes(bytes))

def to_bytes(addr: Ticket.TransportAddress) -> Maybe<&2,List<&2,U32>>:
  match addr:
    case Ticket.Custom{hi,lo,+data}:
      Bool.pick(Maybe<&2,List<&2,U32>>,are_bytes(data),Some{LE.push_word(lo,LE.push_word(hi,data))},None{})
    case _:
      None{}
