import Base

# Internal strings contain one Char per UTF-8 octet. URL delimiters are ASCII.
# Percent encoding therefore operates on the original octets.
def octets(s: String) -> List<&2,U32>:
  match s:
    case SNil{}:
      []
    case SCon{c,t}:
      Con{Char.to_u32(c),octets(t)}

def text(bytes: List<&2,U32>) -> String:
  match bytes:
    case Nil{}:
      ""
    case Con{b,t}:
      SCon{Char.from_u32(b),text(t)}

def between(+n: U32, lo: U32, hi: U32) -> Bool:
  U32.is_ge(n,lo) && U32.is_le(n,hi)

def letter(+n: U32) -> Bool:
  between(n,65,90) || between(n,97,122)

def digit(n: U32) -> Bool:
  between(n,48,57)

def lower_byte(+n: U32) -> U32:
  Bool.pick(U32,between(n,65,90),U32.add(n,32),n)

def lower(s: String) -> String:
  match s:
    case SNil{}:
      ""
    case SCon{c,t}:
      SCon{Char.from_u32(lower_byte(Char.to_u32(c))),lower(t)}

type Split is Data:
  Split{head: String, rest: String}

def prepend_split(c: Char, result: Split) -> Split:
  Split{head,rest} = result
  Split{SCon{c,head},rest}

def scanned(c: Char, tail: String, cut: Bool, next: Unit -> Split) -> Split:
  match cut:
    case True{}:
      Split{"",SCon{c,tail}}
    case False{}:
      prepend_split(c,next(Unit{}))

def split(~stop: U32 -> Bool, s: String) -> Split:
  match s:
    case SNil{}:
      Split{"",""}
    case SCon{+c,+t}:
      scanned(c,t,stop(Char.to_u32(c)),u => split(~stop,t))

def tail(s: String) -> String:
  match s:
    case SCon{_,r}:
      r
    case SNil{}:
      ""

def trim_left(+s: String) -> String:
  match s:
    case SCon{+c,t}:
      Bool.pick(String,U32.is_le(Char.to_u32(c),32),trim_left(t),s)
    case SNil{}:
      ""

def strip_tabs(s: String) -> String:
  match s:
    case SCon{'\t',t}:
      strip_tabs(t)
    case SCon{'\n',t}:
      strip_tabs(t)
    case SCon{'\r',t}:
      strip_tabs(t)
    case SCon{c,t}:
      SCon{c,strip_tabs(t)}
    case SNil{}:
      ""

def clean(s: String) -> String:
  strip_tabs(String.reverse(trim_left(String.reverse(trim_left(s)))))

def hex_value(+n: U32) -> U32:
  +lower = lower_byte(n)
  Bool.pick(U32,digit(n),U32.sub(n,48),Bool.pick(U32,between(lower,97,102),U32.sub(lower,87),16))

def hex_char(+n: U32) -> Char:
  Char.from_u32(Bool.pick(U32,U32.is_lt(n,10),U32.add(n,48),U32.add(n,55)))

type Component is Data:
  Opaque{}
  Path{}
  UserInfo{}
  Query{special: Bool}
  Fragment{}

def path_byte(+n: U32) -> Bool:
  U32.is_eq(n,32) || U32.is_eq(n,34) || U32.is_eq(n,35) || U32.is_eq(n,60) ||
    U32.is_eq(n,62) || U32.is_eq(n,63) || U32.is_eq(n,96) || U32.is_eq(n,123) || U32.is_eq(n,125)

def escape_in(component: Component, +n: U32) -> Bool:
  match component:
    case Opaque{}:
      False{}
    case Path{}:
      path_byte(n)
    case UserInfo{}:
      path_byte(n) || U32.is_eq(n,47) || U32.is_eq(n,58) || U32.is_eq(n,59) || U32.is_eq(n,61) ||
        U32.is_eq(n,64) || between(n,91,94) || U32.is_eq(n,124)
    case Query{special}:
      U32.is_eq(n,32) || U32.is_eq(n,34) || U32.is_eq(n,35) || U32.is_eq(n,60) ||
        U32.is_eq(n,62) || (special && U32.is_eq(n,39))
    case Fragment{}:
      U32.is_eq(n,32) || U32.is_eq(n,34) || U32.is_eq(n,60) || U32.is_eq(n,62) || U32.is_eq(n,96)

def escaped(+n: U32, t: String, encode: Bool) -> String:
  match encode:
    case True{}:
      SCon{'%',SCon{hex_char(U32.shrn(n,4n)),SCon{hex_char(U32.and(n,15)),t}}}
    case False{}:
      SCon{Char.from_u32(n),t}

def encode(+component: Component, s: String) -> String:
  match s:
    case SNil{}:
      ""
    case SCon{c,t}:
      +n = Char.to_u32(c)
      escaped(n,encode(component,t),U32.is_lt(n,32) || U32.is_ge(n,127) || escape_in(component,n))

def decoded(+a: U32, +b: U32, rest: Unit -> Maybe<&2,String>) -> Maybe<&2,String>:
  Maybe.bind(&2,U32,String,
    Bool.pick(Maybe<&2,U32>,U32.is_lt(a,16) && U32.is_lt(b,16),Some{U32.or(U32.shln(a,4n),b)},None{}),
    byte => Maybe.map(&2,String,String,t => SCon{Char.from_u32(byte),t},rest(Unit{})))

# A literal or malformed percent escape is forbidden in a special URL host.
def unescape(s: String) -> Maybe<&2,String>:
  match s:
    case SCon{'%',SCon{x,SCon{y,t}}}:
      decoded(hex_value(Char.to_u32(x)),hex_value(Char.to_u32(y)),u => unescape(t))
    case SCon{'%',_}:
      None{}
    case SCon{c,t}:
      Maybe.map(&2,String,String,rest => SCon{c,rest},unescape(t))
    case SNil{}:
      Some{""}

def all(~test: U32 -> Bool, s: String) -> Bool:
  match s:
    case SNil{}:
      True{}
    case SCon{c,t}:
      test(Char.to_u32(c)) && all(~test,t)

def forbidden(+n: U32) -> Bool:
  U32.is_eq(n,0) || U32.is_eq(n,9) || U32.is_eq(n,10) || U32.is_eq(n,13) || U32.is_eq(n,32) ||
    U32.is_eq(n,35) || U32.is_eq(n,47) || U32.is_eq(n,58) || U32.is_eq(n,60) || U32.is_eq(n,62) ||
    U32.is_eq(n,63) || U32.is_eq(n,64) || between(n,91,94) || U32.is_eq(n,124)

def domain_byte(+n: U32) -> Bool:
  U32.is_gt(n,32) && U32.is_ne(n,127) && U32.is_ne(n,37) && Bool.not(forbidden(n))
