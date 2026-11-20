import Base
import ./idna_data.bend as D
import ./idna_table.bend as Table
import ./url_text.bend as T

# UTF-8 is validated by the URL parser before this conversion.
def width(+lead: U32) -> U32:
  Bool.pick(U32,U32.is_lt(lead,128),1,Bool.pick(U32,U32.is_lt(lead,224),2,Bool.pick(U32,U32.is_lt(lead,240),3,4)))

def continuation(n: U32, c: Char) -> U32:
  U32.or(U32.shln(n,6n),U32.and(Char.to_u32(c),63))

@unsafe
def utf8(s: String) -> String:
  match s:
    case SNil{}:
      ""
    case SCon{c,tail}:
      +n = Char.to_u32(c)
      next_scalar(tail,n,width(n))

@unsafe
def next_scalar(s: String, n: U32, size: U32) -> String:
  match s size:
    case _ 1:
      SCon{Char.from_u32(n),utf8(s)}
    case SCon{b,tail} 2:
      SCon{Char.from_u32(continuation(U32.and(n,31),b)),utf8(tail)}
    case SCon{b,SCon{c,tail}} 3:
      SCon{Char.from_u32(continuation(continuation(U32.and(n,15),b),c)),utf8(tail)}
    case SCon{b,SCon{c,SCon{d,tail}}} 4:
      SCon{Char.from_u32(continuation(continuation(continuation(U32.and(n,7),b),c),d)),utf8(tail)}
    case _ _:
      ""

def ascii(+n: U32) -> Bool:
  U32.is_lt(n,128)

def hangul_tail(+t: U32) -> String:
  Bool.pick(String,U32.is_eq(t,0),"",SCon{Char.from_u32(U32.add(4519,t)),SNil{}})

def decomposed(+cp: U32, hangul: Bool) -> String:
  match hangul:
    case False{}:
      SCon{Char.from_u32(cp),SNil{}}
    case True{}:
      +index = U32.sub(cp,44032)
      lead = U32.add(4352,U32.div(index,588))
      vowel = U32.add(4449,U32.mod(U32.div(index,28),21))
      SCon{Char.from_u32(lead),SCon{Char.from_u32(vowel),hangul_tail(U32.mod(index,28))}}

def scalar(+cp: U32) -> String:
  decomposed(cp,T.between(cp,44032,55203))

def expansion(size: Nat, +index: U32) -> String:
  match size:
    case 0n:
      ""
    case 1n+rest:
      cp = Table.at(D.sequence_page(U32.shrn(index,5n)),U32.to_nat(U32.and(index,31)))
      scalar(cp) ++ expansion(rest,U32.inc(index))

def mapped(cp: U32, +v: U32, seq: Bool) -> Maybe<&2,String>:
  match v seq:
    case 0 _:
      Some{scalar(cp)}
    case 1 _:
      None{}
    case 2 _:
      Some{""}
    case _ True{}:
      +offset = U32.sub(v,1179648)
      Some{expansion(U32.to_nat(U32.shrn(offset,16n)),U32.and(offset,65535))}
    case _ False{}:
      Some{scalar(U32.mod(U32.add(cp,U32.sub(v,3)),1114112))}

def transform(+cp: U32, basic: Bool) -> Maybe<&2,String>:
  match basic:
    case True{}:
      Some{SCon{Char.from_u32(T.lower_byte(cp)),SNil{}}}
    case False{}:
      +v = D.mapping(cp)
      mapped(cp,v,U32.is_ge(v,1179648))

def joined(a: Maybe<&2,String>, b: Maybe<&2,String>) -> Maybe<&2,String>:
  match a b:
    case Some{x} Some{y}:
      Some{x ++ y}
    case _ _:
      None{}

def map_text(s: String) -> Maybe<&2,String>:
  match s:
    case SNil{}:
      Some{""}
    case SCon{c,t}:
      +n = Char.to_u32(c)
      joined(transform(n,ascii(n)),map_text(t))

def combining(cp: U32, basic: Bool) -> U32:
  match basic:
    case True{}:
      0
    case False{}:
      U32.and(D.properties(cp),255)

def ccc(c: Char) -> U32:
  +n = Char.to_u32(c)
  combining(n,ascii(n))

@unsafe
def order_mark(+c: Char, +cl: U32, s: String) -> String:
  match s:
    case SNil{}:
      SCon{c,SNil{}}
    case SCon{+d,tail}:
      +dl = ccc(d)
      insert_mark(c,cl,d,tail,U32.is_eq(dl,0) || U32.is_le(cl,dl))

@unsafe
def insert_mark(c: Char, cl: U32, d: Char, tail: String, here: Bool) -> String:
  match here:
    case True{}:
      SCon{c,SCon{d,tail}}
    case False{}:
      SCon{d,order_mark(c,cl,tail)}

def prepend_ordered(c: Char, cl: U32, sorted: String, starter: Bool) -> String:
  match starter:
    case True{}:
      SCon{c,sorted}
    case False{}:
      order_mark(c,cl,sorted)

def ordered(s: String) -> String:
  match s:
    case SNil{}:
      ""
    case SCon{+c,t}:
      +cl = ccc(c)
      prepend_ordered(c,cl,ordered(t),U32.is_eq(cl,0))

def pair(+a: U32, +b: U32, lv: Bool, lvt: Bool) -> U32:
  match lv lvt:
    case True{} _:
      U32.add(44032,U32.mul(U32.add(U32.mul(U32.sub(a,4352),21),U32.sub(b,4449)),28))
    case _ True{}:
      U32.add(a,U32.sub(b,4519))
    case _ _:
      Table.composition(D.composition_bucket(U32.and(U32.xor(U32.mul(a,31),b),511)),a,b)

def composite(+a: U32, +b: U32, allowed: Bool) -> U32:
  match allowed:
    case False{}:
      0
    case True{}:
      pair(a,b,T.between(a,4352,4370) && T.between(b,4449,4469),
        T.between(a,44032,55203) && U32.is_eq(U32.mod(U32.sub(a,44032),28),0) && T.between(b,4520,4546))

@unsafe
def compose(tail: String, +starter: U32, marks: String, +last: U32) -> String:
  match tail:
    case SNil{}:
      SCon{Char.from_u32(starter),String.reverse(marks)}
    case SCon{+c,rest}:
      +cl = ccc(c)
      +cp = Char.to_u32(c)
      next_composition(rest,starter,marks,last,cp,cl,composite(starter,cp,U32.is_eq(last,0) || U32.is_lt(last,cl)))

@unsafe
def next_composition(tail: String, starter: U32, marks: String, last: U32, +cp: U32, cl: U32, result: U32) -> String:
  match cl result:
    case 0 0:
      SCon{Char.from_u32(starter),String.reverse(marks) ++ compose(tail,cp,"",0)}
    case _ 0:
      compose(tail,starter,SCon{Char.from_u32(cp),marks},cl)
    case _ _:
      compose(tail,result,marks,last)

def composed(s: String) -> String:
  match s:
    case SNil{}:
      ""
    case SCon{c,t}:
      compose(t,Char.to_u32(c),"",0)

def normalize(s: String) -> Maybe<&2,String>:
  Maybe.map(&2,String,String,x => composed(ordered(x)),map_text(s))
