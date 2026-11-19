import Base
import ./discovery.bend as Bytes
import ./relay.bend as Wire

type Value is Data:
  ByteString{bytes: List<&2,U32>}
  Integer{decimal: List<&2,U32>}
  Sequence{values: List<&2,Value>}
  Dictionary{values: List<&2,Value>}

type Token is Data:
  Atom{value: Value, tail: List<&2,U32>}
  OpenContainer{dict: Bool, tail: List<&2,U32>}
  CloseContainer{tail: List<&2,U32>}
  EndInput{}
  BadToken{}

def text_token(part: Wire.Split) -> Token:
  match part:
    case Wire.Prefix{text,tail}:
      Atom{ByteString{text},tail}
    case Wire.ShortPrefix{}:
      BadToken{}

def digit(+c: U32) -> Bool:
  U32.is_ge(c,48) && U32.is_le(c,57)

def text_length(+fuel: Nat, input: List<&2,U32>, +n: U32, good: Bool) -> Token:
  match fuel input good:
    case _ Con{58,tail} True{}:
      text_token(Wire.split_peer(U32.to_nat(n),tail,[]))
    case 1n+k Con{+c,tail} True{}:
      text_length(k,tail,U32.add(U32.mul(n,10),U32.sub(c,48)),digit(c) && U32.is_gt(n,0))
    case _ _ _:
      BadToken{}

def integer_chars(+fuel: Nat, input: List<&2,U32>, reversed: List<&2,U32>, good: Bool)
    -> Token:
  match fuel input good:
    case _ Con{101,tail} True{}:
      Atom{Integer{List.reverse(&2,U32,reversed)},tail}
    case 1n+k Con{+c,tail} True{}:
      integer_chars(k,tail,Con{c,reversed},digit(c))
    case _ _ _:
      BadToken{}

def integer_first(input: List<&2,U32>, negative: Bool) -> Token:
  match input negative:
    case Con{48,Con{101,tail}} False{}:
      Atom{Integer{[48]},tail}
    case Con{48,_} _:
      BadToken{}
    case Con{+c,tail} False{}:
      integer_chars(18n,tail,[c],digit(c))
    case Con{+c,tail} True{}:
      integer_chars(18n,tail,[c,45],digit(c))
    case _ _:
      BadToken{}

def integer(input: List<&2,U32>) -> Token:
  match input:
    case Con{45,tail}:
      integer_first(tail,True{})
    case _:
      integer_first(input,False{})

def next(input: List<&2,U32>) -> Token:
  match input:
    case Nil{}:
      EndInput{}
    case Con{100,tail}:
      OpenContainer{True{},tail}
    case Con{108,tail}:
      OpenContainer{False{},tail}
    case Con{101,tail}:
      CloseContainer{tail}
    case Con{105,tail}:
      integer(tail)
    case Con{+c,tail}:
      text_length(3n,tail,U32.sub(c,48),digit(c))

def key_less(+a: U32, +b: U32, rest: Bool) -> Bool:
  U32.is_lt(a,b) || (U32.is_eq(a,b) && rest)

def less(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Con{_,_}:
      True{}
    case Con{x,xs} Con{y,ys}:
      key_less(x,y,less(xs,ys))
    case _ _:
      False{}

def ordered(values: List<&2,Value>, previous: Maybe<&2,List<&2,U32>>) -> Bool:
  match values previous:
    case Nil{} _:
      True{}
    case Con{_,Con{ByteString{key},tail}} None{}:
      ordered(tail,Some{key})
    case Con{_,Con{ByteString{+key},tail}} Some{higher}:
      less(key,higher) && ordered(tail,Some{key})
    case _ _:
      False{}

type Frame is Data:
  ParseContainer{dict: Bool, values: List<&2,Value>, parent: Frame}
  ParseRoot{values: List<&2,Value>}

def push(frame: Frame, item: Value) -> Frame:
  match frame:
    case ParseRoot{values}:
      ParseRoot{Con{item,values}}
    case ParseContainer{dict,values,parent}:
      ParseContainer{dict,Con{item,values},parent}

type Reduction is Data:
  ResumeParent{parent: Frame}
  InvalidReduction{}

def pop_dict(+reversed: List<&2,Value>, parent: Frame, canonical: Bool) -> Reduction:
  match canonical:
    case True{}:
      ResumeParent{push(parent,Dictionary{List.reverse(&2,Value,reversed)})}
    case False{}:
      InvalidReduction{}

def pop(frame: Frame) -> Reduction:
  match frame:
    case ParseContainer{True{},+reversed,parent}:
      pop_dict(reversed,parent,ordered(reversed,None{}))
    case ParseContainer{False{},reversed,parent}:
      ResumeParent{push(parent,Sequence{List.reverse(&2,Value,reversed)})}
    case ParseRoot{_}:
      InvalidReduction{}

def finish(frame: Frame) -> Maybe<&2,Value>:
  match frame:
    case ParseRoot{Con{value,Nil{}}}:
      Some{value}
    case _:
      None{}

def scan(+fuel: Nat, token: Token, +frame: Frame, reduced: Reduction, +depth: U32, room: Bool)
    -> Maybe<&2,Value>:
  match fuel token reduced room:
    case 1n+k Atom{value,tail} _ _:
      scan(k,next(tail),push(frame,value),InvalidReduction{},depth,room)
    case 1n+k OpenContainer{dict,tail} _ True{}:
      scan(k,next(tail),ParseContainer{dict,[],frame},InvalidReduction{},U32.inc(depth),U32.is_lt(depth,15))
    case 1n+k CloseContainer{+tail} InvalidReduction{} _:
      scan(k,CloseContainer{tail},frame,pop(frame),depth,room)
    case 1n+k CloseContainer{tail} ResumeParent{parent} _:
      scan(k,next(tail),parent,InvalidReduction{},U32.sub(depth,1),True{})
    case _ EndInput{} _ _:
      finish(frame)
    case _ _ _ _:
      None{}

def decode_sized(bytes: List<&2,U32>, size: Wire.Size) -> Maybe<&2,Value>:
  match size:
    case Wire.Length{n}:
      scan(U32.to_nat(U32.inc(U32.mul(n,2))),next(bytes),ParseRoot{[]},InvalidReduction{},0,True{})
    case _:
      None{}

def decode(+bytes: List<&2,U32>) -> Maybe<&2,Value>:
  decode_sized(bytes,Wire.measure_limited(bytes,2048))

def selected(value: Value, remainder: Maybe<&2,Value>, matched: Bool) -> Maybe<&2,Value>:
  match matched:
    case True{}:
      Some{value}
    case False{}:
      remainder

def select(values: List<&2,Value>, +key: List<&2,U32>) -> Maybe<&2,Value>:
  match values:
    case Con{ByteString{name},Con{value,tail}}:
      selected(value,select(tail,key),Bytes.bytes_eq(key,name))
    case _:
      None{}

def get(values: List<&2,Value>, key: String) -> Maybe<&2,Value>:
  select(values,Bytes.keyword(key))

def string(+bytes: List<&2,U32>) -> List<&2,U32>:
  List.append(&2,U32,Bytes.keyword(U32.show(Bytes.count_bytes(bytes))),Con{58,bytes})
