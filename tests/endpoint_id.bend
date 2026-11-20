import Base
import ../src/endpoint_id.bend as Id

def spelling(result: Maybe<&2,String>) -> String:
  match result:
    case Some{text}:
      text
    case None{}:
      "invalid"

def canonical(key: Maybe<&2,List<&2,U32>>) -> String:
  match key:
    case Some{bytes}:
      spelling(Id.format(bytes))
    case None{}:
      "invalid"

def print_keys(inputs: List<String>) -> IO(Unit):
  match inputs:
    case Nil{}:
      IO.pure(Unit,Unit{})
    case Con{input,rest}:
      do IO<Unit>:
        result : Maybe<&2,List<&2,U32>> <- Id.parse(input)
        IO.print(canonical(result))
        print_keys(rest)

def assert_result(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.pure(Unit,Unit{})
    case False{}:
      IO.die(Unit,1,"unexpected endpoint ID result")

def assert_key(text: String, expected: String) -> IO(Unit):
  do IO<Unit>:
    result : Maybe<&2,List<&2,U32>> <- Id.parse(text)
    assert_result(String.eq(canonical(result),expected))

def vectors() -> IO(Unit):
  +hex = {"ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6" : String}
  do IO<Unit>:
    assert_key(hex,hex)
    assert_key("VZMP7CBTEQNMQLLP65QRARXNM62QOLIUFRMI2ADD5FBNTJ2VAK3A",hex)
    assert_key("vzmp7cbteqnmqllp65qrarxnm62qoliufrmi2add5fbntj2vak3a",hex)
    assert_key("AE58FF8833241AC82D6FF7611046ED67B5072D142C588D0063E942D9A75502B6","invalid")
    assert_key("VZMP7CBTEQNMQLLP65QRARXNM62QOLIUFRMI2ADD5FBNTJ2VAK3B","invalid")
    assert_key("0200000000000000000000000000000000000000000000000000000000000000","invalid")
    assert_key("foobarbaz","invalid")
    IO.print("PASS Iroh endpoint ID text and point validation vectors")

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_]:
      vectors()
    case Con{_,rest}:
      print_keys(rest)
    case _:
      vectors()

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
