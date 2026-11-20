import Base

# The Unicode database is paged into 32-entry blocks. A stored word consists
# of two 12-bit digits based at U+4000 so every literal is printable.
def word(hi: Char, lo: Char) -> U32:
  U32.or(U32.shln(U32.and(Char.to_u32(hi),4095),12n),U32.and(Char.to_u32(lo),4095))

def range_word(s: String, +index: U32) -> U32:
  match s:
    case SCon{end,SCon{hi,SCon{lo,tail}}}:
      Bool.pick(U32,U32.is_lt(index,U32.and(Char.to_u32(end),4095)),word(hi,lo),range_word(tail,index))
    case _:
      0

def at(s: String, n: Nat) -> U32:
  match s n:
    case SCon{a,SCon{b,_}} 0n:
      word(a,b)
    case SCon{_,SCon{_,tail}} 1n+left:
      at(tail,left)
    case _ _:
      0

def composition(s: String, +first: U32, +second: U32) -> U32:
  match s:
    case SCon{a,SCon{b,SCon{c,SCon{d,SCon{e,SCon{f,tail}}}}}}:
      Bool.pick(U32,U32.is_eq(first,word(a,b)) && U32.is_eq(second,word(c,d)),
        word(e,f),composition(tail,first,second))
    case _:
      0
