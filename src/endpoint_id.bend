import Base
import ./ed25519.bend as Ed25519

def low_mask(bits: U32) -> U32:
  U32.sub(U32.shln(1,U32.to_nat(bits)),1)

def digit_match(index: U32, same: Bool, next: Unit -> Maybe<&2,U32>) -> Maybe<&2,U32>:
  match same:
    case True{}:
      Some{index}
    case False{}:
      next(Unit{})

def digit_index(+value: U32, chars: List<&2,Char>, +index: U32) -> Maybe<&2,U32>:
  match chars:
    case Nil{}:
      None{}
    case Con{head,tail}:
      digit_match(index,U32.is_eq(value,Char.to_u32(head)),_ => digit_index(value,tail,U32.add(index,1)))

def lowercase(+value: U32, upper: Bool) -> U32:
  match upper:
    case True{}:
      U32.add(value,32)
    case False{}:
      value

def digit(code: U32, +base32: Bool, ascii_upper: Bool) -> Maybe<&2,U32>:
  match base32:
    case True{}:
      digit_index(lowercase(code,ascii_upper),String.to_list("abcdefghijklmnopqrstuvwxyz234567"),0)
    case False{}:
      digit_index(code,String.to_list("0123456789abcdef"),0)

def prepend_digit(value: Maybe<&2,List<&2,U32>>, first: U32) -> Maybe<&2,List<&2,U32>>:
  match value:
    case Some{rest}:
      Some{Con{first,rest}}
    case None{}:
      None{}

def read_digit(value: Maybe<&2,U32>, next: Unit -> Maybe<&2,List<&2,U32>>) -> Maybe<&2,List<&2,U32>>:
  match value:
    case Some{n}:
      prepend_digit(next(Unit{}),n)
    case None{}:
      None{}

def read_digits(chars: List<&2,Char>, +base32: Bool) -> Maybe<&2,List<&2,U32>>:
  match chars:
    case Nil{}:
      Some{[]}
    case Con{head,tail}:
      +code = Char.to_u32(head)
      read_digit(digit(code,base32,U32.is_ge(code,65) && U32.is_le(code,90)),_ => read_digits(tail,base32))

def finish_bits(word: U32, output: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  match word:
    case 0:
      Some{List.reverse(&2,U32,output)}
    case _:
      None{}

def unpack(fuel: Nat, +digits: List<&2,U32>, +width: U32, +word: U32, +bits: U32, output: List<&2,U32>,
    full: Bool) -> Maybe<&2,List<&2,U32>>:
  match fuel digits full:
    case 1n+remaining _ True{}:
      +rest = U32.sub(bits,8)
      unpack(remaining,digits,width,U32.and(word,low_mask(rest)),rest,
        Con{U32.shrn(word,U32.to_nat(rest)),output},False{})
    case 1n+remaining Con{value,tail} False{}:
      +expanded = U32.add(bits,width)
      unpack(remaining,tail,width,U32.or(U32.shln(word,U32.to_nat(width)),value),expanded,output,U32.is_ge(expanded,8))
    case _ Nil{} False{}:
      finish_bits(word,output)
    case _ _ _:
      None{}

def unpack_digits(value: Maybe<&2,List<&2,U32>>, width: U32) -> Maybe<&2,List<&2,U32>>:
  match value:
    case Some{digits}:
      unpack(96n,digits,width,0,0,[],False{})
    case None{}:
      None{}

def decode_length(length: Nat, text: String) -> Maybe<&2,List<&2,U32>>:
  match length:
    case 64n:
      unpack_digits(read_digits(String.to_list(text),False{}),4)
    case 52n:
      unpack_digits(read_digits(String.to_list(text),True{}),5)
    case _:
      None{}

# Decode Iroh's lowercase hexadecimal or unpadded RFC 4648 base32 spelling.
# Use parse to also validate the compressed Ed25519 point.
def decode(+text: String) -> Maybe<&2,List<&2,U32>>:
  decode_length(String.length(text),text)

def hex_char(+nibble: U32) -> Char:
  Char.from_u32(U32.add(U32.add(nibble,48),U32.mul(39,Bool.to_u32(U32.is_ge(nibble,10)))))

def hex_byte(tail: Maybe<&2,List<&2,Char>>, +byte: U32, valid: Bool) -> Maybe<&2,List<&2,Char>>:
  match tail valid:
    case Some{rest} True{}:
      Some{Con{hex_char(U32.shrn(byte,4n)),Con{hex_char(U32.and(byte,15)),rest}}}
    case _ _:
      None{}

def hex_bytes(bytes: List<&2,U32>, left: Nat) -> Maybe<&2,List<&2,Char>>:
  match bytes left:
    case Nil{} 0n:
      Some{[]}
    case Con{+byte,tail} 1n+more:
      hex_byte(hex_bytes(tail,more),byte,U32.is_le(byte,255))
    case _ _:
      None{}

def hex_text(chars: Maybe<&2,List<&2,Char>>) -> Maybe<&2,String>:
  match chars:
    case Some{value}:
      Some{String.from_list(value)}
    case None{}:
      None{}

def format(bytes: List<&2,U32>) -> Maybe<&2,String>:
  hex_text(hex_bytes(bytes,32n))

def validated(+bytes: List<&2,U32>, valid: Bool) -> Maybe<&2,List<&2,U32>>:
  match valid:
    case True{}:
      Some{bytes}
    case False{}:
      None{}

def validate_decoded(result: Maybe<&2,List<&2,U32>>) -> IO(Maybe<&2,List<&2,U32>>):
  match result:
    case Some{+bytes}:
      do IO<Maybe<&2,List<&2,U32>>>:
        valid : Bool <- Ed25519.valid_public_key(bytes)
        return validated(bytes,valid)
    case None{}:
      IO.pure(Maybe<&2,List<&2,U32>>,None{})

def parse(text: String) -> IO(Maybe<&2,List<&2,U32>>):
  validate_decoded(decode(text))
