import Base
import ../src/discovery.bend as Dns
import ../src/pkarr.bend as Pkarr

def key() -> List<&2,U32>:
  [25,127,107,35,225,108,133,50,198,171,200,56,250,205,94,167,
   137,190,12,118,178,146,3,52,3,155,250,139,61,54,141,97]

# Signed with the seed of 32 bytes of value 42. The u64 maximum
# exercises the canonical BEP44 decimal transcript at its upper bound.
def wire() -> List<&2,U32>:
  [25,127,107,35,225,108,133,50,198,171,200,56,250,205,94,167,
   137,190,12,118,178,146,3,52,3,155,250,139,61,54,141,97,
   231,74,153,83,225,161,0,149,34,43,48,99,16,60,249,144,
   105,210,207,84,184,138,145,126,130,28,157,151,65,253,21,44,
   155,61,165,101,134,221,38,34,38,239,101,57,59,138,109,189,
   12,26,22,115,237,12,209,34,102,122,115,122,7,11,168,11,
   255,255,255,255,255,255,255,255,0,0,128,0,0,0,0,3,
   0,0,0,0,5,95,105,114,111,104,52,100,102,57,115,115,
   101,57,98,112,49,110,117,102,116,105,109,51,121,104,120,105,
   117,107,54,119,54,114,53,104,100,100,115,115,107,106,121,103,
   112,121,100,117,120,55,101,115,120,106,115,116,105,111,111,0,
   0,16,0,1,0,0,0,30,0,26,25,97,100,100,114,61,
   49,57,50,46,49,54,56,46,57,54,46,49,52,53,58,54,
   48,49,54,53,192,12,0,16,0,1,0,0,0,30,0,26,
   25,97,100,100,114,61,50,49,51,46,50,48,56,46,49,53,
   55,46,56,55,58,54,48,49,54,53,192,12,0,16,0,1,
   0,0,0,30,0,42,41,114,101,108,97,121,61,104,116,116,
   112,115,58,47,47,101,117,119,49,45,49,46,114,101,108,97,
   121,46,105,114,111,104,46,110,101,116,119,111,114,107,46,47]

def valid(proof: Pkarr.Verification) -> Bool:
  match proof:
    case Pkarr.Verified{timestamp,Con{Dns.Address{a},Con{Dns.Address{b},Con{Dns.RelayUrl{r},Nil{}}}}}:
      Dns.bytes_eq(timestamp,List.replicate(U32,8n,255)) &&
        Dns.bytes_eq(a,Dns.keyword("192.168.96.145:60165")) &&
        Dns.bytes_eq(b,Dns.keyword("213.208.157.87:60165")) &&
        Dns.bytes_eq(r,Dns.keyword("https://euw1-1.relay.iroh.network./"))
    case _:
      False{}

def tamper(wire_bytes: List<&2,U32>) -> List<&2,U32>:
  List.reverse(&2,U32,Con{0,Dns.drop(1n,List.reverse(&2,U32,wire_bytes))})

def report(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("PASS signed Pkarr TXT packet, wrong-key rejection and tamper rejection")
    case False{}:
      IO.die(Unit,1,"Pkarr decoded the wrong endpoint records")

def assert_results(good: Pkarr.Verification, wrong: Pkarr.Verification, altered: Pkarr.Verification) -> IO(Unit):
  match wrong altered:
    case Pkarr.WrongKey{} Pkarr.InvalidSignature{}:
      report(valid(good))
    case _ _:
      IO.die(Unit,1,"Pkarr accepted a wrong key or changed packet")

def records() -> List<&2,Dns.Attribute>:
  [Dns.Address{Dns.keyword("192.168.96.145:60165")},
    Dns.Address{Dns.keyword("213.208.157.87:60165")},
    Dns.RelayUrl{Dns.keyword("https://euw1-1.relay.iroh.network./")}]

def report_signed(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("PASS canonical Pkarr signing bytes and mismatched signing-key rejection")
    case False{}:
      IO.die(Unit,1,"Pkarr signing bytes differ from the independent fixture")

def assert_signed(packet: List<&2,U32>, wrong_seed: Result<&1,&1,U32 & String,List<&2,U32>>) -> IO(Unit):
  match wrong_seed:
    case Fail{_}:
      report_signed(Dns.bytes_eq(packet,wire()))
    case Done{_}:
      IO.die(Unit,1,"Pkarr signed bytes for a mismatched endpoint")

def main() -> IO(Unit):
  do IO<Unit>:
    good : Pkarr.Verification <- Pkarr.verify_relay_body(key(),Dns.drop(32n,wire()))
    wrong : Pkarr.Verification <- Pkarr.verify(List.replicate(U32,32n,0),wire())
    altered : Pkarr.Verification <- Pkarr.verify(key(),tamper(wire()))
    assert_results(good,wrong,altered)
    signed : List<&2,U32> <- IO.try(List<&2,U32>,
      Pkarr.sign(List.replicate(U32,32n,42),key(),List.replicate(U32,8n,255),records(),30))
    wrong_seed : Result<&1,&1,U32 & String,List<&2,U32>> <-
      Pkarr.sign(List.replicate(U32,32n,73),key(),List.replicate(U32,8n,255),records(),30)
    assert_signed(signed,wrong_seed)
