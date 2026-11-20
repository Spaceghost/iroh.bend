import Base
import ./relay.bend as Relay

# RFC 6455 server-side framing for the binary relay stream. The caller
# meters each transport read before passing its bytes to receive.
type Message is Data:
  NoMessage{}
  Fragment{opcode: U32, size: U32, reversed: List<&2,U32>}

type Frame is Data:
  Binary{bytes: List<&2,U32>}
  TextFrame{bytes: List<&2,U32>}
  Ping{bytes: List<&2,U32>}
  Pong{bytes: List<&2,U32>}
  CloseFrame{bytes: List<&2,U32>}

type Phase is Data:
  Header{}
  Length{opcode: U32, final: Bool}
  Extended{opcode: U32, final: Bool, left: U32, minimum: U32, size: U32}
  Mask{opcode: U32, final: Bool, size: U32, left: U32, key: U32}
  Payload{opcode: U32, final: Bool, left: U32, key: U32,
    size: U32, reversed: List<&2,U32>}

type Decoder is Data:
  DecoderState{phase: Phase, message: Message}

type Read is Data:
  Waiting{decoder: Decoder}
  Received{frame: Frame, decoder: Decoder, remaining: List<&2,U32>}
  Rejected{status: U32}

type Step is Data:
  Next{decoder: Decoder}
  FrameReady{frame: Frame, decoder: Decoder}
  InvalidFrame{status: U32}

def decoder() -> Decoder:
  DecoderState{Header{},NoMessage{}}

def opcode_allowed(opcode: U32, final: Bool, message: Message) -> Bool:
  match opcode message:
    case 0 Fragment{_,_,_}:
      True{}
    case 1 NoMessage{}:
      True{}
    case 2 NoMessage{}:
      True{}
    case 8 _:
      final
    case 9 _:
      final
    case 10 _:
      final
    case _ _:
      False{}

def close_status(+status: U32) -> Bool:
  (U32.is_ge(status,1000) && U32.is_le(status,1003)) ||
  (U32.is_ge(status,1007) && U32.is_le(status,1014)) ||
  (U32.is_ge(status,3000) && U32.is_le(status,4999))

def finish_close(body: List<&2,U32>, status: Bool, utf8: Bool) -> Step:
  match status utf8:
    case False{} _:
      InvalidFrame{1002}
    case True{} False{}:
      InvalidFrame{1007}
    case True{} True{}:
      FrameReady{CloseFrame{body},decoder()}

def close_frame(+body: List<&2,U32>) -> Step:
  match body:
    case Nil{}:
      FrameReady{CloseFrame{body},decoder()}
    case Con{hi,Con{lo,text}}:
      finish_close(body,close_status(U32.or(U32.shln(hi,8n),lo)),Relay.utf8_scan(text,Relay.Lead{}))
    case _:
      InvalidFrame{1002}

def finish_text(bytes: List<&2,U32>, valid: Bool) -> Step:
  match valid:
    case True{}:
      FrameReady{TextFrame{bytes},decoder()}
    case False{}:
      InvalidFrame{1007}

def text(+bytes: List<&2,U32>) -> Step:
  finish_text(bytes,Relay.utf8_scan(bytes,Relay.Lead{}))

def finish(+opcode: U32, final: Bool, size: U32, reversed: List<&2,U32>, message: Message) -> Step:
  match opcode final:
    case 8 _:
      close_frame(List.reverse(&2,U32,reversed))
    case 9 _:
      FrameReady{Ping{List.reverse(&2,U32,reversed)},DecoderState{Header{},message}}
    case 10 _:
      FrameReady{Pong{List.reverse(&2,U32,reversed)},DecoderState{Header{},message}}
    case 1 True{}:
      text(List.reverse(&2,U32,reversed))
    case _ True{}:
      FrameReady{Binary{List.reverse(&2,U32,reversed)},decoder()}
    case _ False{}:
      Next{DecoderState{Header{},Fragment{opcode,size,reversed}}}

def payload(opcode: U32, final: Bool, left: U32, key: U32, size: U32, reversed: List<&2,U32>,
    message: Message) -> Step:
  match left:
    case 0:
      finish(opcode,final,size,reversed,message)
    case _:
      Next{DecoderState{Payload{opcode,final,left,key,size,reversed},message}}

def admit_data(opcode: U32, final: Bool, +size: U32, key: U32, used: U32,
    reversed: List<&2,U32>, oversized: Bool) -> Step:
  match oversized:
    case True{}:
      InvalidFrame{1009}
    case False{}:
      payload(opcode,final,size,key,U32.add(used,size),reversed,NoMessage{})

def start_data(opcode: U32, final: Bool, +size: U32, key: U32, +used: U32,
    reversed: List<&2,U32>, +limit: U32) -> Step:
  admit_data(opcode,final,size,key,used,reversed,
    U32.is_gt(used,limit) || U32.is_gt(size,U32.sub(limit,used)))

def finish_mask(+opcode: U32, final: Bool, +size: U32, key: U32, message: Message, limit: U32) -> Step:
  match opcode message:
    case 0 Fragment{kind,used,reversed}:
      start_data(kind,final,size,key,used,reversed,limit)
    case 1 _:
      start_data(opcode,final,size,key,0,[],limit)
    case 2 _:
      start_data(opcode,final,size,key,0,[],limit)
    case _ _:
      payload(opcode,final,size,key,size,[],message)

def mask(opcode: U32, final: Bool, +size: U32, left: U32, key: U32, message: Message, limit: U32) -> Step:
  match opcode left message:
    case _ 1 _:
      finish_mask(opcode,final,size,key,message,limit)
    case _ _ _:
      Next{DecoderState{Mask{opcode,final,size,U32.sub(left,1),key},message}}

def length(opcode: U32, final: Bool, +width: U32, message: Message, masked: Bool, short: Bool,
    control: Bool) -> Step:
  match width masked short control:
    case _ False{} _ _:
      InvalidFrame{1002}
    case _ True{} True{} _:
      Next{DecoderState{Mask{opcode,final,width,4,0},message}}
    case _ True{} False{} True{}:
      InvalidFrame{1002}
    case 126 True{} False{} False{}:
      Next{DecoderState{Extended{opcode,final,2,126,0},message}}
    case _ True{} False{} False{}:
      Next{DecoderState{Extended{opcode,final,8,65536,0},message}}

def extended(opcode: U32, final: Bool, left: U32, minimum: U32, size: U32, message: Message,
    high_bit: Bool, oversized: Bool, canonical: Bool) -> Step:
  match left high_bit oversized canonical:
    case 8 True{} _ _:
      InvalidFrame{1002}
    case _ _ True{} _:
      InvalidFrame{1009}
    case 1 _ False{} False{}:
      InvalidFrame{1002}
    case 1 _ False{} True{}:
      Next{DecoderState{Mask{opcode,final,size,4,0},message}}
    case _ _ False{} _:
      Next{DecoderState{Extended{opcode,final,U32.sub(left,1),minimum,size},message}}

def header(opcode: U32, final: Bool, message: Message, valid: Bool) -> Step:
  match valid:
    case True{}:
      Next{DecoderState{Length{opcode,final},message}}
    case False{}:
      InvalidFrame{1002}

def consume(phase: Phase, +message: Message, +byte: U32, limit: U32, byte_ok: Bool) -> Step:
  match phase byte_ok:
    case _ False{}:
      InvalidFrame{1002}
    case Header{} True{}:
      +opcode = U32.and(byte,15)
      +final = U32.is_ge(byte,128)
      header(opcode,final,message,U32.is_eq(U32.and(byte,112),0) && opcode_allowed(opcode,final,message))
    case Length{+opcode,final} True{}:
      +width = U32.and(byte,127)
      length(opcode,final,width,message,U32.is_ge(byte,128),U32.is_lt(width,126),U32.is_ge(opcode,8))
    case Extended{opcode,final,left,+minimum,+size} True{}:
      +next = U32.or(U32.shln(size,8n),byte)
      extended(opcode,final,left,minimum,next,message,
        U32.is_ge(byte,128),U32.is_gt(size,16777215) || U32.is_gt(next,limit),U32.is_ge(next,minimum))
    case Mask{opcode,final,size,left,key} True{}:
      mask(opcode,final,size,left,U32.or(U32.shln(key,8n),byte),message,limit)
    case Payload{opcode,final,left,+key,size,reversed} True{}:
      decoded = U32.xor(byte,U32.shrn(key,24n))
      next_key = U32.or(U32.shln(key,8n),U32.shrn(key,24n))
      payload(opcode,final,U32.sub(left,1),next_key,size,Con{decoded,reversed},message)

def read_bytes(bytes: List<&2,U32>, +limit: U32, step: Step) -> Read:
  match bytes step:
    case rest FrameReady{frame,next}:
      Received{frame,next,rest}
    case _ InvalidFrame{status}:
      Rejected{status}
    case Nil{} Next{next}:
      Waiting{next}
    case Con{+byte,rest} Next{DecoderState{phase,message}}:
      read_bytes(rest,limit,consume(phase,message,byte,limit,U32.is_le(byte,255)))

# Emit one event at a time so an HTTP/TLS driver can apply backpressure
# without copying or dropping any coalesced frames. The caller handles the
# closing handshake when receiving CloseFrame or Rejected.
def receive(decoder: Decoder, bytes: List<&2,U32>, limit: U32) -> Read:
  read_bytes(bytes,limit,Next{decoder})

def size_header(+size: U32, short: Bool, medium: Bool) -> List<&2,U32>:
  match short medium:
    case True{} _:
      [size]
    case False{} True{}:
      [126,U32.shrn(size,8n),U32.and(size,255)]
    case False{} False{}:
      [127,0,0,0,0,U32.shrn(size,24n),U32.and(U32.shrn(size,16n),255),
        U32.and(U32.shrn(size,8n),255),U32.and(size,255)]

def encode_payload(opcode: U32, bytes: List<&2,U32>, measured: Relay.Size) -> Maybe<&2,List<&2,U32>>:
  match measured:
    case Relay.Length{+size}:
      header = size_header(size,U32.is_lt(size,126),U32.is_lt(size,65536))
      Some{Con{U32.or(128,opcode),List.append(&2,U32,header,bytes)}}
    case _:
      None{}

def encode_close(encoded: Step) -> Maybe<&2,List<&2,U32>>:
  match encoded:
    case FrameReady{CloseFrame{+bytes},_}:
      encode_payload(8,bytes,Relay.measure_limited(bytes,125))
    case _:
      None{}

# Server frames have no mask. Only the relay's binary and control opcodes
# are emitted. Fragmentation is accepted on receive; writes are contiguous.
def encode(frame: Frame) -> Maybe<&2,List<&2,U32>>:
  match frame:
    case Binary{+bytes}:
      encode_payload(2,bytes,Relay.measure_limited(bytes,65544))
    case TextFrame{_}:
      None{}
    case Ping{+bytes}:
      encode_payload(9,bytes,Relay.measure_limited(bytes,125))
    case Pong{+bytes}:
      encode_payload(10,bytes,Relay.measure_limited(bytes,125))
    case CloseFrame{bytes}:
      encode_close(close_frame(bytes))
