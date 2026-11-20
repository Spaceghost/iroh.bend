import Base
import ./url_text.bend as T

# RFC 3492 parameters for DNS labels. Internal strings hold Unicode scalars.
def threshold(+k: U32, +bias: U32) -> U32:
  Bool.pick(U32,U32.is_le(k,bias),1,U32.max(1,U32.min(26,U32.sub(k,bias))))

@unsafe
def adapt_scale(+d: U32, k: U32, again: Bool) -> U32:
  match again:
    case True{}:
      +next = U32.div(d,35)
      adapt_scale(next,U32.add(k,36),U32.is_gt(next,455))
    case False{}:
      U32.add(k,U32.div(U32.mul(36,d),U32.add(d,38)))

def adapt(delta: U32, count: U32, first: Bool) -> U32:
  +d = U32.div(delta,Bool.pick(U32,first,700,2))
  +scaled = U32.add(d,U32.div(d,count))
  adapt_scale(scaled,0,U32.is_gt(scaled,455))

def glyph(+v: U32) -> Char:
  Char.from_u32(Bool.pick(U32,U32.is_lt(v,26),U32.add(v,97),U32.add(v,22)))

@unsafe
def digits(+q: U32, +k: U32, +bias: U32, +t: U32, rev: String, done: Bool) -> String:
  match done:
    case True{}:
      SCon{glyph(q),rev}
    case False{}:
      +base = U32.sub(36,t)
      +excess = U32.sub(q,t)
      +next = U32.div(excess,base)
      +next_k = U32.add(k,36)
      +next_t = threshold(next_k,bias)
      digits(next,next_k,bias,next_t,SCon{glyph(U32.add(t,U32.mod(excess,base))),rev},U32.is_lt(next,next_t))

def basic(input: String) -> String:
  match input:
    case SNil{}:
      ""
    case SCon{+c,tail}:
      +rest = basic(tail)
      Bool.pick(String,U32.is_lt(Char.to_u32(c),128),SCon{c,rest},rest)

def minimum(input: String, +n: U32, best: U32) -> U32:
  match input:
    case SNil{}:
      best
    case SCon{c,tail}:
      +p = Char.to_u32(c)
      minimum(tail,n,U32.min(best,Bool.pick(U32,U32.is_ge(p,n),p,1114112)))

type Encoding is Data:
  Enc{handled: U32, delta: U32, bias: U32, rev: String}

def occurrence(p: U32, n: U32, basic_count: U32, state: Encoding, equal: Bool) -> Encoding:
  Enc{+h,+d,+bias,rev} = state
  match equal:
    case True{}:
      +t = threshold(36,bias)
      Enc{U32.inc(h),0,adapt(d,U32.inc(h),U32.is_eq(h,basic_count)),digits(d,36,bias,t,rev,U32.is_lt(d,t))}
    case False{}:
      Enc{h,U32.add(d,Bool.to_u32(U32.is_lt(p,n))),bias,rev}

def scan(input: String, +n: U32, +basic_count: U32, state: Encoding) -> Encoding:
  match input:
    case SNil{}:
      state
    case SCon{c,tail}:
      +p = Char.to_u32(c)
      scan(tail,n,basic_count,occurrence(p,n,basic_count,state,U32.is_eq(p,n)))

@unsafe
def encode_round(+input: String, +count: U32, +ascii_count: U32, +n: U32, state: Encoding, done: Bool) -> String:
  Enc{+h,d,bias,rev} = state
  match done:
    case True{}:
      String.reverse(rev)
    case False{}:
      +m = minimum(input,n,1114112)
      delta = U32.add(d,U32.mul(U32.sub(m,n),U32.inc(h)))
      advance(input,count,ascii_count,U32.inc(m),scan(input,m,ascii_count,Enc{h,delta,bias,rev}))

@unsafe
def advance(input: String, +count: U32, ascii_count: U32, n: U32, state: Encoding) -> String:
  Enc{+h,d,bias,rev} = state
  encode_round(input,count,ascii_count,n,Enc{h,U32.inc(d),bias,rev},U32.is_eq(h,count))

def encode(+label: String) -> String:
  +ascii = basic(label)
  +size = U32.from_nat(String.length(ascii))
  +total = U32.from_nat(String.length(label))
  rev = String.reverse(ascii)
  start = Bool.pick(String,U32.is_eq(size,0),"",SCon{'-',rev})
  encode_round(label,total,size,128,Enc{size,0,72,start},U32.is_eq(total,size))

def digit(+c: U32) -> U32:
  +p = T.lower_byte(c)
  Bool.pick(U32,T.between(p,97,122),U32.sub(p,97),Bool.pick(U32,T.digit(c),U32.sub(c,22),36))

type Variable is Data:
  WordRead{value: U32, tail: String}
  InvalidWord{}

@unsafe
def more_digits(tail: String, +i: U32, +w: U32, +k: U32, bias: U32, +t: U32, +v: U32, fits: Bool) -> Variable:
  match fits:
    case False{}:
      InvalidWord{}
    case True{}:
      +value = U32.add(i,U32.mul(v,w))
      continue_word(tail,value,w,U32.add(k,36),bias,U32.sub(36,t),U32.is_lt(v,t))

@unsafe
def continue_word(tail: String, +i: U32, +w: U32, +k: U32, +bias: U32, +base: U32, done: Bool) -> Variable:
  match tail done:
    case _ True{}:
      WordRead{i,tail}
    case SCon{c,rest} False{}:
      +v = digit(Char.to_u32(c))
      +weight = U32.mul(w,base)
      allowed = U32.is_le(w,U32.div(4294967295,base)) && U32.is_lt(v,36) &&
        U32.is_le(v,U32.div(U32.sub(4294967295,i),U32.max(1,weight)))
      more_digits(rest,i,weight,k,bias,threshold(k,bias),v,allowed)
    case SNil{} False{}:
      InvalidWord{}

def insert(s: String, c: Char, at: Nat) -> String:
  match s at:
    case SCon{head,tail} 1n+left:
      SCon{head,insert(tail,c,left)}
    case _ _:
      SCon{c,s}

@unsafe
def decoded(word: Variable, label: String, +n: U32, +last: U32, +count: U32, first: Bool) -> Maybe<&2,String>:
  match word:
    case WordRead{+i,tail}:
      +size = U32.inc(count)
      +jump = U32.div(i,size)
      +cp = U32.add(n,jump)
      +at = U32.mod(i,size)
      ok = U32.is_le(jump,U32.sub(1114111,n)) && Bool.not(T.between(cp,55296,57343))
      decoded_point(tail,label,cp,at,size,adapt(U32.sub(i,last),size,first),ok)
    case InvalidWord{}:
      None{}

@unsafe
def decoded_point(tail: String, label: String, +cp: U32, +at: U32, size: U32, bias: U32, valid: Bool) -> Maybe<&2,String>:
  match valid:
    case True{}:
      decode_round(tail,insert(label,Char.from_u32(cp),U32.to_nat(at)),cp,U32.inc(at),bias,size,False{})
    case False{}:
      None{}

@unsafe
def decode_round(input: String, label: String, n: U32, +i: U32, bias: U32, count: U32, first: Bool) -> Maybe<&2,String>:
  match input:
    case SNil{}:
      Some{label}
    case SCon{c,tail}:
      decoded(continue_word(SCon{c,tail},i,1,36,bias,1,False{}),label,n,i,count,first)

def hyphen(n: U32) -> Bool:
  U32.is_eq(n,45)

def decode_parts(parts: T.Split) -> Maybe<&2,String>:
  match parts:
    case T.Split{_,SCon{'-',SNil{}}}:
      None{}
    case T.Split{SNil{},_}:
      None{}
    case T.Split{suffix,SCon{'-',+prefix}}:
      decode_round(String.reverse(suffix),String.reverse(prefix),128,0,72,U32.from_nat(String.length(prefix)),True{})
    case T.Split{suffix,SNil{}}:
      decode_round(String.reverse(suffix),"",128,0,72,0,True{})
    case _:
      None{}

def decode(suffix: String) -> Maybe<&2,String>:
  decode_parts(T.split(~hyphen,String.reverse(suffix)))
