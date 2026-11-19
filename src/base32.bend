import Base

def digit(+bits: U32) -> U32:
  U32.add(U32.add(bits, 48), U32.mul(39, Bool.to_u32(U32.is_ge(bits, 10))))

# Convert the low 20 bits into four DNSSEC base32 characters (MSB first).
def encode_half(+bits: U32) -> U32:
  a = digit(U32.and(U32.shrn(bits, 15n), 31))
  b = digit(U32.and(U32.shrn(bits, 10n), 31))
  c = digit(U32.and(U32.shrn(bits, 5n), 31))
  d = digit(U32.and(bits, 31))
  U32.or(U32.or(U32.shln(a, 24n), U32.shln(b, 16n)),
         U32.or(U32.shln(c, 8n), d))
