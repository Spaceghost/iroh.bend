import Base
import ./url_text.bend as T
import ./ip.bend as Ip

def keep_number(valid: Bool, value: U32, next: U32 -> Maybe<&2,U32>) -> Maybe<&2,U32>:
  match valid:
    case True{}:
      next(value)
    case False{}:
      None{}

def digits(s: String, +base: U32, +limit: U32, +n: U32) -> Maybe<&2,U32>:
  match s:
    case SNil{}:
      Some{n}
    case SCon{c,t}:
      +d = T.hex_value(Char.to_u32(c))
      keep_number(U32.is_lt(d,base) && U32.is_le(d,limit) && U32.is_le(n,U32.div(U32.sub(limit,d),base)),
        U32.add(U32.mul(n,base),d),v => digits(t,base,limit,v))

type Radix is Data:
  Radix{base: U32, body: String}

def radix(s: String) -> Radix:
  match s:
    case SCon{'0',SCon{'x',t}}:
      Radix{16,t}
    case SCon{'0',SCon{'X',t}}:
      Radix{16,t}
    case SCon{'0',SCon{c,t}}:
      Radix{8,SCon{c,t}}
    case _:
      Radix{10,s}

def number_in(r: Radix, limit: U32) -> Maybe<&2,U32>:
  Radix{base,s} = r
  digits(s,base,limit,0)

def ipv4_number(s: String, limit: U32) -> Maybe<&2,U32>:
  match s:
    case SNil{}:
      None{}
    case SCon{_,_}:
      number_in(radix(s),limit)

def show_ipv4(+n: U32) -> String:
  Ip.ipv4(U32.shrn(n,24n),U32.and(U32.shrn(n,16n),255),U32.and(U32.shrn(n,8n),255),U32.and(n,255))

def ipv4_parts(parts: List<&2,String>, +shift: U32, limit: U32, +acc: U32) -> Maybe<&2,String>:
  match parts shift:
    case [last] _:
      Maybe.map(&2,U32,String,n => show_ipv4(U32.or(acc,n)),ipv4_number(last,limit))
    case Con{head,rest} 0:
      None{}
    case Con{head,rest} _:
      Maybe.bind(&2,U32,String,ipv4_number(head,255),n => ipv4_parts(rest,U32.sub(shift,8),U32.shrn(limit,8n),
        U32.or(acc,U32.shln(n,U32.to_nat(shift)))))
    case _ _:
      None{}

def all_hex(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{c,t}:
      U32.is_lt(T.hex_value(Char.to_u32(c)),16) && all_hex(t)

def numeric_end(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{'0',SCon{'x',t}}:
      all_hex(t)
    case SCon{'0',SCon{'X',t}}:
      all_hex(t)
    case _:
      T.all(~T.digit,s)

def numeric_host(last: Maybe<&2,String>, parts: List<&2,String>, domain: String) -> Maybe<&2,String>:
  match last:
    case Some{label}:
      Bool.pick(Maybe<&2,String>,numeric_end(label),ipv4_parts(parts,24,4294967295,0),Some{domain})
    case None{}:
      Some{domain}

def finish_domain(reversed: List<&2,String>, domain: String) -> Maybe<&2,String>:
  match reversed:
    case Con{SNil{},Con{+last,rest}}:
      numeric_host(Some{last},List.reverse(&2,String,Con{last,rest}),domain)
    case Con{+last,rest}:
      numeric_host(Some{last},List.reverse(&2,String,Con{last,rest}),domain)
    case Nil{}:
      None{}

def domain_or_ipv4(+domain: String) -> Maybe<&2,String>:
  finish_domain(List.reverse(&2,String,String.split(domain,'.')),domain)

def decimal_octet(s: String) -> Maybe<&2,U32>:
  match s:
    case SNil{}:
      None{}
    case SCon{'0',SCon{_,_}}:
      None{}
    case _:
      digits(s,10,255,0)

def ipv4_pair(a: Maybe<&2,U32>, b: Maybe<&2,U32>) -> Maybe<&2,U32>:
  match a b:
    case Some{x} Some{y}:
      Some{U32.or(U32.shln(x,8n),y)}
    case _ _:
      None{}

def two_words(a: Maybe<&2,U32>, b: Maybe<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  match a b:
    case Some{x} Some{y}:
      Some{[x,y]}
    case _ _:
      None{}

def ipv6_tail(parts: List<&2,String>) -> Maybe<&2,List<&2,U32>>:
  match parts:
    case [a,b,c,d]:
      two_words(ipv4_pair(decimal_octet(a),decimal_octet(b)),ipv4_pair(decimal_octet(c),decimal_octet(d)))
    case _:
      None{}

def word(s: String, valid: Bool) -> Maybe<&2,U32>:
  match valid:
    case True{}:
      digits(s,16,65535,0)
    case False{}:
      None{}

def short_word(+s: String) -> Maybe<&2,U32>:
  word(s,Bool.not(String.is_empty(s)) && Nat.is_le(String.length(s),4n))

def append_word(head: Maybe<&2,U32>, tail: Maybe<&2,List<&2,U32>>) -> Maybe<&2,List<&2,U32>>:
  match head tail:
    case Some{h} Some{t}:
      Some{Con{h,t}}
    case _ _:
      None{}

def final_word(+s: String, dotted: Bool) -> Maybe<&2,List<&2,U32>>:
  match dotted:
    case True{}:
      ipv6_tail(String.split(s,'.'))
    case False{}:
      append_word(short_word(s),Some{[]})

def parse_words(parts: List<&2,String>, at_end: Bool) -> Maybe<&2,List<&2,U32>>:
  match parts:
    case [+s]:
      final_word(s,at_end && String.contains(s,"."))
    case Con{head,tail}:
      append_word(short_word(head),parse_words(tail,at_end))
    case Nil{}:
      Some{[]}

def words(s: String, at_end: Bool) -> Maybe<&2,List<&2,U32>>:
  match s:
    case SNil{}:
      Some{[]}
    case _:
      parse_words(String.split(s,':'),at_end)

type Halves is Data:
  Whole{text: String}
  Elided{left: String, right: String}

def prepend_half(c: Char, halves: Halves) -> Halves:
  match halves:
    case Whole{s}:
      Whole{SCon{c,s}}
    case Elided{left,right}:
      Elided{SCon{c,left},right}

def halves(s: String) -> Halves:
  match s:
    case SCon{':',SCon{':',t}}:
      Elided{"",t}
    case SCon{c,t}:
      prepend_half(c,halves(t))
    case SNil{}:
      Whole{""}

def trim_zero(s: String) -> String:
  match s:
    case SCon{'0',SCon{c,t}}:
      trim_zero(SCon{c,t})
    case _:
      s

def show_word(+n: U32) -> String:
  a = T.hex_char(U32.shrn(n,12n))
  b = T.hex_char(U32.and(U32.shrn(n,8n),15))
  c = T.hex_char(U32.and(U32.shrn(n,4n),15))
  d = T.hex_char(U32.and(n,15))
  T.lower(trim_zero(SCon{a,SCon{b,SCon{c,SCon{d,SNil{}}}}}))

def show_words(xs: List<&2,U32>) -> List<&2,String>:
  match xs:
    case Nil{}:
      []
    case Con{h,t}:
      Con{show_word(h),show_words(t)}

def zeros(xs: List<&2,U32>) -> U32:
  match xs:
    case Con{0,t}:
      U32.inc(zeros(t))
    case _:
      0

type Run is Data:
  ZeroRun{at: U32, size: U32}

def longer(+best: Run, at: U32, +size: U32) -> Run:
  ZeroRun{_,n} = best
  Bool.pick(Run,U32.is_gt(size,n),ZeroRun{at,size},best)

def longest(+xs: List<&2,U32>, +at: U32, best: Run) -> Run:
  match xs:
    case Nil{}:
      best
    case Con{_,tail}:
      longest(tail,U32.inc(at),longer(best,at,zeros(xs)))

def compress(+xs: List<&2,U32>, run: Run) -> String:
  match run:
    case ZeroRun{_,0}:
      String.join(show_words(xs),":")
    case ZeroRun{_,1}:
      String.join(show_words(xs),":")
    case ZeroRun{+at,size}:
      left = List.take(&2,U32,xs,U32.to_nat(at))
      right = List.drop(&2,U32,xs,U32.to_nat(U32.add(at,size)))
      String.join(show_words(left),":") ++ ("::" ++ String.join(show_words(right),":"))

def render(+xs: List<&2,U32>, valid: Bool) -> Maybe<&2,String>:
  match valid:
    case True{}:
      Some{"[" ++ (compress(xs,longest(xs,0,ZeroRun{0,0})) ++ "]")}
    case False{}:
      None{}

def complete(left: Maybe<&2,List<&2,U32>>, right: Maybe<&2,List<&2,U32>>, compressed: Bool) -> Maybe<&2,String>:
  match left right:
    case Some{+a} Some{+b}:
      +n = Nat.add(List.length(&2,U32,a),List.length(&2,U32,b))
      fill = List.replicate(U32,Nat.sub(8n,n),0)
      render(List.append(&2,U32,a,List.append(&2,U32,fill,b)),
        Bool.pick(Bool,compressed,Nat.is_lt(n,8n),Nat.is_eq(n,8n)))
    case _ _:
      None{}

def ipv6_halves(h: Halves) -> Maybe<&2,String>:
  match h:
    case Whole{s}:
      complete(words(s,True{}),Some{[]},False{})
    case Elided{left,right}:
      complete(words(left,False{}),words(right,True{}),True{})

def ipv6(s: String) -> Maybe<&2,String>:
  ipv6_halves(halves(s))
