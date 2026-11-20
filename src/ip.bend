import Base

def ipv4(a: U32, b: U32, c: U32, d: U32) -> String:
  left = String.append(U32.show(a),String.append(".",U32.show(b)))
  right = String.append(U32.show(c),String.append(".",U32.show(d)))
  String.append(left,String.append(".",right))

def hex_digit(+n: U32, digit: Bool) -> Char:
  match digit:
    case True{}:
      Char.from_u32(U32.add(48,n))
    case False{}:
      Char.from_u32(U32.add(87,n))

def hex_char(+n: U32) -> Char:
  hex_digit(n,U32.is_lt(n,10))

def hex_byte(+byte: U32, rest: List<&2,Char>) -> List<&2,Char>:
  Con{hex_char(U32.shrn(byte,4n)),Con{hex_char(U32.and(byte,15)),rest}}

def ipv6_chars(bytes: List<&2,U32>) -> List<&2,Char>:
  match bytes:
    case [hi,lo]:
      hex_byte(hi,hex_byte(lo,[]))
    case Con{hi,Con{lo,tail}}:
      hex_byte(hi,hex_byte(lo,Con{Char.from_u32(58),ipv6_chars(tail)}))
    case _:
      []
