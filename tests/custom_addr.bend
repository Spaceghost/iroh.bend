import Base
import ../src/custom_addr.bend as Custom
import ../src/endpoint_ticket.bend as Ticket
import ../src/endpoint_id.bend as Hex

def raw_text(value: Result<&2,&2,String,Ticket.TransportAddress>) -> String:
  match value:
    case Done{addr}:
      Maybe.default(&2,String,Custom.format(addr),"invalid address")
    case Fail{message}:
      message

def roundtrip(addr: Ticket.TransportAddress, bytes: Maybe<&2,List<&2,U32>>) -> String:
  match bytes:
    case Some{+raw}:
      +text = Maybe.default(&2,String,Custom.format(addr),"invalid address")
      hex = Maybe.default(&2,String,Hex.hex_text(Hex.hex_bytes(raw,List.length(&2,U32,raw))),"invalid bytes")
      Bool.pick(String,String.eq(raw_text(Custom.from_bytes(raw)),text),String.append(text,String.append(" ",hex)),"roundtrip failed")
    case None{}:
      "invalid bytes"

def converted(value: Result<&2,&2,Custom.ParseError,Ticket.TransportAddress>) -> String:
  match value:
    case Done{+addr}:
      roundtrip(addr,Custom.to_bytes(addr))
    case Fail{Custom.MissingSeparator{}}:
      "missing '_' separator"
    case Fail{Custom.InvalidId{}}:
      "invalid id"
    case Fail{Custom.InvalidData{}}:
      "invalid data"

def one(text: String) -> String:
  converted(Custom.parse(text))

def check(valid: Bool, message: String) -> IO(Unit):
  match valid:
    case True{}:
      IO.pure(Unit,Unit{})
    case False{}:
      IO.die(Unit,1,message)

def expect(+input: String, expected: String) -> IO(Unit):
  actual = one(input)
  check(String.eq(actual,expected),String.append("unexpected custom address result for ",input))

def vectors() -> IO(Unit):
  do IO<Unit>:
    expect("0_","0_ 0000000000000000")
    expect("1_a1b2c3d4e5f6","1_a1b2c3d4e5f6 0100000000000000a1b2c3d4e5f6")
    expect("2a_abababababababababababababababababababababababababababababababab",
      "2a_abababababababababababababababababababababababababababababababab 2a00000000000000abababababababababababababababababababababababababababababababab")
    expect("+0000000000000DEADBEEF_0102","deadbeef_0102 efbeadde000000000102")
    expect("123456789ABCDEF0_00ff","123456789abcdef0_00ff f0debc9a7856341200ff")
    expect("ffffffffffffffff_","ffffffffffffffff_ ffffffffffffffff")
    expect("10000000000000000_","invalid id")
    expect("x","missing '_' separator")
    expect("_00","invalid id")
    expect("+_","invalid id")
    expect("0x1_00","invalid id")
    expect("2a_FF","invalid data")
    expect("2a_a","invalid data")
    expect("2a__","invalid data")
    check(String.eq(raw_text(Custom.from_bytes([1,2,3,4,5,6,7])),"data too short"),"short custom address")
    check(String.eq(raw_text(Custom.from_bytes([0,0,0,0,0,0,0,0,256])),"expected bytes"),"custom payload exceeds a byte")
    check(Maybe.is_none(&2,List<&2,U32>,Custom.to_bytes(Ticket.IPv4{[127,0,0,1],7})),"IP treated as custom address")
    check(Maybe.is_none(&2,String,Custom.format(Ticket.Custom{0,1,[256]})),"non-byte custom address was formatted")
    IO.print("PASS Iroh custom transport address text and little-endian bytes")

def binary(bytes: List<&2,U32>) -> String:
  raw_text(Custom.from_bytes(bytes))

def print_cases(~convert: String -> String, inputs: List<String>) -> IO(Unit):
  match inputs:
    case Nil{}:
      IO.pure(Unit,Unit{})
    case Con{item,rest}:
      do IO<Unit>:
        IO.print(convert(item))
        print_cases(~convert,rest)
