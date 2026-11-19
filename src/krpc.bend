import Base
import ./bencode.bend as Ben
import ./discovery.bend as Bytes
import ./pkarr.bend as Pkarr
import ./relay.bend as Wire

def cat(a: List<&2,U32>, b: List<&2,U32>) -> List<&2,U32>:
  List.append(&2,U32,a,b)

def literal(prefix: String, tail: List<&2,U32>) -> List<&2,U32>:
  cat(Bytes.keyword(prefix),tail)

def request(args: List<&2,U32>, method: String, id: List<&2,U32>, tx: List<&2,U32>) -> List<&2,U32>:
  literal("d1:ad2:id",cat(Ben.string(id),cat(args,literal("e1:q3:",
    literal(method,literal("2:roi1e1:t",cat(Ben.string(tx),Bytes.keyword("1:y1:qe"))))))))

def get(id: List<&2,U32>, tx: List<&2,U32>, target: List<&2,U32>) -> List<&2,U32>:
  request(literal("6:target",Ben.string(target)),"get",id,tx)

def put_fields(key: List<&2,U32>, signature: List<&2,U32>, decimal: List<&2,U32>,
    value: List<&2,U32>, token: List<&2,U32>) -> List<&2,U32>:
  literal("1:k",cat(Ben.string(key),literal("3:seqi",cat(decimal,literal("e3:sig",
    cat(Ben.string(signature),literal("5:token",cat(Ben.string(token),literal("1:v",Ben.string(value))))))))))

def put_item(id: List<&2,U32>, tx: List<&2,U32>, token: List<&2,U32>, key: List<&2,U32>,
    signature: List<&2,U32>, timestamp: List<&2,U32>, value: List<&2,U32>, valid: Bool)
    -> Maybe<&2,List<&2,U32>>:
  match valid:
    case True{}:
      Some{request(put_fields(key,signature,Pkarr.ascii(Pkarr.decimal(timestamp,[0])),value,token),"put",id,tx)}
    case False{}:
      None{}

def put(id: List<&2,U32>, tx: List<&2,U32>, token: List<&2,U32>, envelope: Pkarr.Signed)
    -> Maybe<&2,List<&2,U32>>:
  match envelope:
    case Pkarr.Envelope{key,signature,Con{+head,tail},value}:
      put_item(id,tx,token,key,signature,Con{head,tail},value,U32.is_lt(head,128))
    case _:
      None{}

type Reply is Data:
  KrpcResponse{fields: List<&2,Ben.Value>}
  KrpcError{code: List<&2,U32>, detail: List<&2,U32>}
  InvalidKrpcReply{}

def payload(fields: Maybe<&2,Ben.Value>, error: Maybe<&2,Ben.Value>, response: Bool, failure: Bool) -> Reply:
  match fields error response failure:
    case Some{Ben.Dictionary{dict}} None{} True{} _:
      KrpcResponse{dict}
    case None{} Some{Ben.Sequence{Con{Ben.Integer{code},Con{Ben.ByteString{detail},Nil{}}}}} _ True{}:
      KrpcError{code,detail}
    case _ _ _ _:
      InvalidKrpcReply{}

def classify(+dict: List<&2,Ben.Value>, kind: Maybe<&2,Ben.Value>,
    transaction: Maybe<&2,Ben.Value>, expected: List<&2,U32>) -> Reply:
  match kind transaction:
    case Some{Ben.ByteString{[114]}} Some{Ben.ByteString{tx}}:
      payload(Ben.get(dict,"r"),Ben.get(dict,"e"),Bytes.bytes_eq(expected,tx),False{})
    case Some{Ben.ByteString{[101]}} Some{Ben.ByteString{tx}}:
      payload(Ben.get(dict,"r"),Ben.get(dict,"e"),False{},Bytes.bytes_eq(expected,tx))
    case _ _:
      InvalidKrpcReply{}

def reply_value(decoded: Maybe<&2,Ben.Value>, tx: List<&2,U32>) -> Reply:
  match decoded:
    case Some{Ben.Dictionary{+dict}}:
      classify(dict,Ben.get(dict,"y"),Ben.get(dict,"t"),tx)
    case _:
      InvalidKrpcReply{}

def reply(bytes: List<&2,U32>, tx: List<&2,U32>) -> Reply:
  reply_value(Ben.decode(bytes),tx)

def text(value: Maybe<&2,Ben.Value>) -> Maybe<&2,List<&2,U32>>:
  match value:
    case Some{Ben.ByteString{bytes}}:
      Some{bytes}
    case _:
      None{}

def integer(value: Maybe<&2,Ben.Value>) -> Maybe<&2,List<&2,U32>>:
  match value:
    case Some{Ben.Integer{decimal}}:
      Some{decimal}
    case _:
      None{}

def same_size(data: List<&2,U32>, valid: Bool) -> Maybe<&2,List<&2,U32>>:
  match valid:
    case True{}:
      Some{data}
    case False{}:
      None{}

def sized(data: List<&2,U32>, measured: Wire.Size, size: U32) -> Maybe<&2,List<&2,U32>>:
  match measured:
    case Wire.Length{n}:
      same_size(data,U32.is_eq(n,size))
    case _:
      None{}

def exact(bytes: Maybe<&2,List<&2,U32>>, +size: U32) -> Maybe<&2,List<&2,U32>>:
  match bytes:
    case Some{+data}:
      sized(data,Wire.measure_limited(data,size),size)
    case None{}:
      None{}

# Convert the canonical nonnegative BEP 44 sequence to Pkarr's 8-byte
# big-endian timestamp. Detect arithmetic overflow before truncation.
type Accumulator is Data:
  Digits{bytes: List<&2,U32>, carry: U32}

def add_digit_byte(rest: Accumulator, byte: U32) -> Accumulator:
  Digits{tail,carry} = rest
  Digits{Con{byte,tail},carry}

def digit_step(reversed: List<&2,U32>, +carry: U32) -> Accumulator:
  match reversed:
    case Nil{}:
      Digits{[],carry}
    case Con{byte,tail}:
      +n = U32.add(U32.mul(byte,10),carry)
      add_digit_byte(digit_step(tail,U32.shrn(n,8n)),U32.and(n,255))

def signed_timestamp(bytes: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  match bytes:
    case Con{+head,tail}:
      same_size(Con{head,tail},U32.is_lt(head,128))
    case _:
      None{}

def timestamp_digits(digits: List<&2,U32>, number: Accumulator) -> Maybe<&2,List<&2,U32>>:
  match digits number:
    case Nil{} Digits{bytes,0}:
      signed_timestamp(List.reverse(&2,U32,bytes))
    case Con{45,_} _:
      None{}
    case Con{digit,tail} Digits{bytes,0}:
      timestamp_digits(tail,digit_step(bytes,U32.sub(digit,48)))
    case _ _:
      None{}

def timestamp(decimal: Maybe<&2,List<&2,U32>>) -> Maybe<&2,List<&2,U32>>:
  match decimal:
    case Some{digits}:
      timestamp_digits(digits,Digits{[0,0,0,0,0,0,0,0],0})
    case None{}:
      None{}

def pack_item(key: Maybe<&2,List<&2,U32>>, signature: Maybe<&2,List<&2,U32>>,
    seq: Maybe<&2,List<&2,U32>>, data: Maybe<&2,List<&2,U32>>) -> Maybe<&2,List<&2,U32>>:
  match key signature seq data:
    case Some{k} Some{sig} Some{s} Some{v}:
      Some{cat(k,cat(sig,cat(s,v)))}
    case _ _ _ _:
      None{}

def item(+fields: List<&2,Ben.Value>) -> Maybe<&2,List<&2,U32>>:
  pack_item(exact(text(Ben.get(fields,"k")),32),exact(text(Ben.get(fields,"sig")),64),
    timestamp(integer(Ben.get(fields,"seq"))),text(Ben.get(fields,"v")))

type CompactNode is Data:
  CompactV4{id: List<&2,U32>, a: U32, b: U32, c: U32, d: U32, port: U32}

def compact_node(part: Wire.Split, next: List<&2,CompactNode>) -> List<&2,CompactNode>:
  match part:
    case Wire.Prefix{id,[a,b,c,d,hi,lo]}:
      Con{CompactV4{id,a,b,c,d,Bytes.be16(hi,lo)},next}
    case _:
      next

def compact_nodes(+fuel: Nat, split: Wire.Split) -> List<&2,CompactNode>:
  match fuel split:
    case 1n+k Wire.Prefix{entry,remaining}:
      compact_node(Wire.split_peer(20n,entry,[]),compact_nodes(k,Wire.split_peer(26n,remaining,[])))
    case _ _:
      []

def nodes_block(bytes: List<&2,U32>, valid: Bool) -> List<&2,CompactNode>:
  match valid:
    case True{}:
      compact_nodes(78n,Wire.split_peer(26n,bytes,[]))
    case False{}:
      []

def nodes_sized(bytes: List<&2,U32>, size: Wire.Size) -> List<&2,CompactNode>:
  match size:
    case Wire.Length{n}:
      nodes_block(bytes,U32.is_eq(U32.mod(n,26),0))
    case _:
      []

def nodes(value: Maybe<&2,List<&2,U32>>) -> List<&2,CompactNode>:
  match value:
    case Some{+bytes}:
      nodes_sized(bytes,Wire.measure_limited(bytes,2048))
    case None{}:
      []
