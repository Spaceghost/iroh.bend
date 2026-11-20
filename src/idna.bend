import Base
import ./url_text.bend as T
import ./idna_normalize.bend as N
import ./idna_data.bend as D
import ./punycode.bend as P

# UTS #46, nontransitional processing with the URL Standard's ASCII deny list.
# Unicode properties use the bit layout in tools/generate_idna.py.
def joining(prop: U32) -> U32:
  U32.and(U32.shrn(prop,12n),7)

def bidi(cp: U32) -> U32:
  U32.and(U32.shrn(D.properties(cp),9n),7)

def right_join(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{c,t}:
      +jt = joining(D.properties(Char.to_u32(c)))
      Bool.pick(Bool,U32.is_eq(jt,4),right_join(t),U32.is_eq(jt,2) || U32.is_eq(jt,3))

def joiner(cp: U32, tail: String, virama: Bool, left: Bool) -> Bool:
  match cp virama:
    case 8205 False{}:
      False{}
    case 8204 False{}:
      left && right_join(tail)
    case _ _:
      True{}

def context(s: String, virama: Bool, +left: Bool) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{c,+tail}:
      +cp = Char.to_u32(c)
      +prop = D.properties(cp)
      +jt = joining(prop)
      joiner(cp,tail,virama,left) && context(tail,U32.is_eq(U32.and(prop,255),9),
        Bool.pick(Bool,U32.is_eq(jt,4),left,U32.is_eq(jt,1) || U32.is_eq(jt,3)))

def legal(+n: U32) -> Bool:
  U32.is_ne(n,46) && T.domain_byte(n)

def contextual(+s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{c,_}:
      U32.is_eq(U32.and(D.properties(Char.to_u32(c)),256),0) &&
        T.all(~(n => legal(n)),s) && context(s,False{},False{})

def bidi_domain(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{c,t}:
      +bc = bidi(Char.to_u32(c))
      U32.is_eq(bc,2) || U32.is_eq(bc,4) || bidi_domain(t)

# 1=L, 2=R/AL, 3=EN, 4=AN, 5=NSM, 6=allowed punctuation/boundary.
def bidi_tail(s: String, +rtl: Bool, +last: U32, +en: Bool, +an: Bool) -> Bool:
  match s:
    case SNil{}:
      Bool.pick(Bool,rtl,(U32.is_eq(last,2) || U32.is_eq(last,3) || U32.is_eq(last,4)) && Bool.not(en && an),
        U32.is_eq(last,1) || U32.is_eq(last,3))
    case SCon{c,t}:
      +bc = bidi(Char.to_u32(c))
      allowed = U32.is_ne(bc,0) && Bool.pick(Bool,rtl,U32.is_ne(bc,1),U32.is_ne(bc,2) && U32.is_ne(bc,4))
      allowed && bidi_tail(t,rtl,Bool.pick(U32,U32.is_eq(bc,5),last,bc),en || U32.is_eq(bc,3),an || U32.is_eq(bc,4))

def bidi_label(s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{c,t}:
      +first = bidi(Char.to_u32(c))
      (U32.is_eq(first,1) || U32.is_eq(first,2)) && bidi_tail(t,U32.is_eq(first,2),first,False{},False{})

type Label is Data:
  Label{unicode: String, ascii: String}

def finish_ace(+label: String, encoded: String, normalized: Maybe<&2,String>) -> Maybe<&2,Label>:
  match normalized:
    case Some{s}:
      Bool.pick(Maybe<&2,Label>,String.eq(s,label) && contextual(label) && Nat.is_le(String.length(label),1000n),
        Some{Label{label,encoded}},None{})
    case None{}:
      None{}

def decoded_ace(+s: String, original: String) -> Maybe<&2,Label>:
  finish_ace(s,original,N.normalize(s))

def ace(encoded: String, suffix: String, allowed: Bool) -> Maybe<&2,Label>:
  match allowed:
    case False{}:
      None{}
    case True{}:
      Maybe.bind(&2,String,Label,P.decode(suffix),s => decoded_ace(s,encoded))

def unicode_label(+s: String, valid: Bool) -> Maybe<&2,Label>:
  match valid:
    case True{}:
      Some{Label{s,"xn--" ++ P.encode(s)}}
    case False{}:
      None{}

def label(+s: String, basic: Bool, prefix: Bool) -> Maybe<&2,Label>:
  match basic prefix:
    case True{} True{}:
      +suffix = String.drop(s,4n)
      ace(s,suffix,Nat.is_le(String.length(suffix),2000n) && Bool.not(String.ends_with(suffix,"-")))
    case False{} True{}:
      None{}
    case True{} False{}:
      Bool.pick(Maybe<&2,Label>,T.all(~(n => legal(n)),s),Some{Label{s,s}},None{})
    case False{} False{}:
      unicode_label(s,Nat.is_le(String.length(s),1000n) && contextual(s))

def cons(head: Maybe<&2,Label>, rest: Maybe<&2,List<&2,Label>>) -> Maybe<&2,List<&2,Label>>:
  match head rest:
    case Some{h} Some{r}:
      Some{Con{h,r}}
    case _ _:
      None{}

def labels(s: List<&2,String>) -> Maybe<&2,List<&2,Label>>:
  match s:
    case Con{+name,tail}:
      cons(label(name,T.all(~(n => N.ascii(n)),name),String.starts_with(name,"xn--")),labels(tail))
    case Nil{}:
      Some{[]}

def has_rtl(s: List<&2,Label>) -> Bool:
  match s:
    case Con{Label{u,_},tail}:
      bidi_domain(u) || has_rtl(tail)
    case Nil{}:
      False{}

def spelled(s: List<&2,Label>, +rtl: Bool) -> Maybe<&2,List<&2,String>>:
  match s:
    case Con{Label{u,a},tail}:
      Maybe.bind(&2,List<&2,String>,List<&2,String>,spelled(tail,rtl),
        parts => Bool.pick(Maybe<&2,List<&2,String>>,Bool.not(rtl) || bidi_label(u),Some{Con{a,parts}},None{}))
    case Nil{}:
      Some{[]}

def assembled(+items: List<&2,Label>) -> Maybe<&2,String>:
  Maybe.map(&2,List<&2,String>,String,parts => String.join(parts,"."),spelled(items,has_rtl(items)))

def converted(s: String) -> Maybe<&2,String>:
  match s:
    case SNil{}:
      None{}
    case _:
      Maybe.bind(&2,List<&2,Label>,String,labels(String.split(s,'.')),items => assembled(items))

def has_ace(names: List<&2,String>) -> Bool:
  match names:
    case Con{name,tail}:
      String.starts_with(name,"xn--") || has_ace(tail)
    case Nil{}:
      False{}

def convert(+s: String, basic: Bool, fast: Bool) -> Maybe<&2,String>:
  match basic fast:
    case True{} True{}:
      Bool.pick(Maybe<&2,String>,T.all(~(n => T.domain_byte(n)),s) && Bool.not(String.is_empty(s)),Some{s},None{})
    case _ _:
      Maybe.bind(&2,String,String,N.normalize(N.utf8(s)),converted)

def to_ascii(+octets: String) -> Maybe<&2,String>:
  +s = T.lower(octets)
  convert(s,T.all(~(n => N.ascii(n)),s),Bool.not(has_ace(String.split(s,'.'))))
