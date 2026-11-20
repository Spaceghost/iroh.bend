import Base
import ../src/punycode.bend as P

def equals(got: Maybe<&2,String>, wanted: String) -> Bool:
  match got:
    case Some{s}:
      String.eq(s,wanted)
    case None{}:
      False{}

def pair(+label: String, +encoded: String) -> Bool:
  String.eq(P.encode(label),encoded) && equals(P.decode(encoded),label)

def rejects(s: String) -> Bool:
  Bool.not(Maybe.is_some(&2,String,P.decode(s)))

def result(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("PASS RFC 3492 Punycode and invalid DNS label suffixes")
    case False{}:
      IO.die(Unit,1,"unexpected Punycode encoding or decoding")

def vectors() -> IO(Unit):
  result(pair("他们为什么不说中文","ihqwcrb4cv8a8dqg056pqjye") &&
    pair("ليهمابتكلموشعربي؟","egbpdaj6bu4bxfgehfvwxn") && pair("mañana","maana-pta") &&
    pair("日本語","wgv71a119e") && pair("παράδειγμα","hxajbheg2az3al") && pair("हिन्दी","j2bd4cyah0f") &&
    pair("😀","e28h") && pair("a☃☃","a-1xpa") && pair("☃-⌘","--dqo34k") &&
    rejects("z") && rejects("9999999999z") && rejects("ib9b") && rejects("a-"))

def main() -> IO(Unit):
  vectors()
