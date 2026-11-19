import Base
import ./relay.bend as Wire

# Single-block BLAKE3 derive-key for the Iroh relay's 16-byte challenge.
# Both the fixed 43-byte context and the material fit one BLAKE3 block.
type Row is Data:
  Four{a: U32, b: U32, c: U32, d: U32}

type Block is Data:
  Rows{a: Row, b: Row, c: Row, d: Row}

type Chaining is Data:
  Pair{a: Row, b: Row}

def rotate(+x: U32, right: Nat, left: Nat) -> U32:
  U32.or(U32.shrn(x, right), U32.shln(x, left))

def mix(a: U32, +b: U32, c: U32, d: U32, x: U32, y: U32) -> Row:
  +a1 = U32.add(U32.add(a, b), x)
  +d1 = rotate(U32.xor(d, a1), 16n, 16n)
  +c1 = U32.add(c, d1)
  +b1 = rotate(U32.xor(b, c1), 12n, 20n)
  +a2 = U32.add(U32.add(a1, b1), y)
  +d2 = rotate(U32.xor(d1, a2), 8n, 24n)
  +c2 = U32.add(c1, d2)
  b2 = rotate(U32.xor(b1, c2), 7n, 25n)
  Four{a2, b2, c2, d2}

def collect(d0: Row, d1: Row, d2: Row, d3: Row) -> Block:
  Four{r0,s1,t2,u3} = d0
  Four{r1,s2,t3,u0} = d1
  Four{r2,s3,t0,u1} = d2
  Four{r3,s0,t1,u2} = d3
  Rows{Four{r0,r1,r2,r3}, Four{s0,s1,s2,s3}, Four{t0,t1,t2,t3}, Four{u0,u1,u2,u3}}

def diagonals(c0: Row, c1: Row, c2: Row, c3: Row, x: Row, y: Row) -> Block:
  Four{a0,b0,c0v,d0} = c0
  Four{a1,b1,c1v,d1} = c1
  Four{a2,b2,c2v,d2} = c2
  Four{a3,b3,c3v,d3} = c3
  Four{x0,x1,x2,x3} = x
  Four{x4,x5,x6,x7} = y
  collect(mix(a0,b1,c2v,d3,x0,x1), mix(a1,b2,c3v,d0,x2,x3),
    mix(a2,b3,c0v,d1,x4,x5), mix(a3,b0,c1v,d2,x6,x7))

def round(state: Block, msg: Block) -> Block:
  Rows{Four{a0,a1,a2,a3},Four{b0,b1,b2,b3},Four{c0,c1,c2,c3},Four{d0,d1,d2,d3}} = state
  Rows{Four{x0,x1,x2,x3},Four{x4,x5,x6,x7},m2,m3} = msg
  diagonals(mix(a0,b0,c0,d0,x0,x1), mix(a1,b1,c1,d1,x2,x3),
    mix(a2,b2,c2,d2,x4,x5), mix(a3,b3,c3,d3,x6,x7), m2, m3)

def permute(msg: Block) -> Block:
  Rows{Four{a,b,c,d},Four{e,f,g,h},Four{i,j,k,l},Four{m,n,o,p}} = msg
  Rows{Four{c,g,d,k}, Four{h,a,e,n}, Four{b,l,m,f}, Four{j,o,p,i}}

def rounds(+count: Nat, state: Block, +msg: Block) -> Block:
  match count:
    case 0n:
      state
    case 1n+k:
      rounds(k, round(state, msg), permute(msg))

def xor_row(a: Row, b: Row) -> Row:
  Four{a0,a1,a2,a3} = a
  Four{b0,b1,b2,b3} = b
  Four{U32.xor(a0,b0), U32.xor(a1,b1), U32.xor(a2,b2), U32.xor(a3,b3)}

def digest(state: Block) -> Chaining:
  Rows{a,b,c,d} = state
  Pair{xor_row(a,c), xor_row(b,d)}

def compress(key: Chaining, msg: Block, length: U32, flags: U32) -> Chaining:
  Pair{a,b} = key
  digest(rounds(7n, Rows{a,b,Four{1779033703,3144134277,1013904242,2773480762},
    Four{0,0,length,flags}}, msg))

def context_key() -> Chaining:
  compress(
    Pair{Four{1779033703,3144134277,1013904242,2773480762},
      Four{1359893119,2600822924,528734635,1541459225}},
    Rows{Four{1752134249,1818587693,1746958689,1935961697},
      Four{1701536104,540112416,1818323043,1735288172},
      Four{1769152613,1952542311,6648437,0},
      Four{0,0,0,0}},
    43, 43)

def le_word(a: U32, b: U32, c: U32, d: U32) -> U32:
  U32.or(U32.or(a, U32.shln(b, 8n)), U32.or(U32.shln(c, 16n), U32.shln(d, 24n)))

def push_word(+word: U32, rest: List<&2,U32>) -> List<&2,U32>:
  Con{U32.and(word,255), Con{U32.and(U32.shrn(word,8n),255),
    Con{U32.and(U32.shrn(word,16n),255), Con{U32.shrn(word,24n),rest}}}}

def push_row(row: Row, rest: List<&2,U32>) -> List<&2,U32>:
  Four{a,b,c,d} = row
  push_word(a, push_word(b, push_word(c, push_word(d, rest))))

def as_bytes(hash: Chaining) -> List<&2,U32>:
  Pair{a,b} = hash
  push_row(a, push_row(b, []))

def compress_nonce(nonce: List<&2,U32>) -> List<&2,U32>:
  match nonce:
    case Con{a,Con{b,Con{c,Con{d,Con{e,Con{f,Con{g,Con{h,Con{i,Con{j,Con{k,Con{l,Con{m,Con{n,Con{o,Con{p,Nil{}}}}}}}}}}}}}}}}}:
      as_bytes(compress(context_key(),
        Rows{Four{le_word(a,b,c,d),le_word(e,f,g,h),le_word(i,j,k,l),le_word(m,n,o,p)},
          Four{0,0,0,0}, Four{0,0,0,0}, Four{0,0,0,0}}, 16, 75))
    case _:
      []


def derive_checked(nonce: List<&2,U32>, size: Wire.Size) -> List<&2,U32>:
  match size:
    case Wire.Length{16}:
      compress_nonce(nonce)
    case _:
      []

def derive(+nonce: List<&2,U32>) -> List<&2,U32>:
  derive_checked(nonce, Wire.measure_limited(nonce, 16))
