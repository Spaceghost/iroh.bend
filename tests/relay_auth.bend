import Base
import ../src/handshake.bend as Handshake
import ../src/relay_auth.bend as Auth
import ../src/relay_exporter.bend as Exporter

def nonce() -> List<&2,U32>:
  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]

def equal(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(x,y) && equal(xs,ys)
    case _ _:
      False{}

def wire_roundtrip(encoded: Handshake.Encoding) -> Handshake.Auth:
  match encoded:
    case Handshake.Encoded{wire}:
      Handshake.decode(wire)
    case Handshake.InvalidEncoding{}:
      Handshake.InvalidAuth{}

def matches_vector(proof: Handshake.Auth) -> Bool:
  match proof:
    case Handshake.ClientProof{key, sig}:
      equal(key, [25,127,107,35,225,108,133,50,198,171,200,56,250,205,94,167,
        137,190,12,118,178,146,3,52,3,155,250,139,61,54,141,97]) &&
      equal(sig, [162,139,94,188,106,147,11,93,128,173,90,202,42,142,72,173,
        74,6,78,105,156,8,102,103,76,139,142,97,165,244,234,148,
        14,232,185,240,103,50,147,2,80,172,7,53,85,90,190,119,
        232,223,116,1,101,237,195,22,59,228,50,240,228,243,207,15])
    case _:
      False{}

def require(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("PASS Iroh relay Ed25519 challenge proof and tamper rejection")
    case False{}:
      IO.die(Unit, 1, "relay challenge signature mismatch")

def test_proof(+proof: Handshake.Auth) -> IO(Unit):
  do IO<Unit>:
    valid : Bool <- Auth.verify_challenge(wire_roundtrip(Handshake.encode(proof)), nonce())
    tampered : Bool <- Auth.verify_challenge(proof, [1,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15])
    require(matches_vector(proof) && valid && Bool.not(tampered))

def exporter_bytes(chars: List<&2,Char>) -> List<&2,U32>:
  match chars:
    case Nil{}:
      []
    case Con{c,rest}:
      Con{Char.to_u32(c),exporter_bytes(rest)}

def same_header(encoded: Maybe<&1,List<&2,U32>>, want: List<&2,U32>) -> Bool:
  match encoded:
    case Some{header}:
      equal(header,want)
    case None{}:
      False{}

def exporter_result(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("PASS Iroh relay TLS exporter proof encoding, verification, and replay rejection")
    case False{}:
      IO.die(Unit,1,"relay exporter proof verification mismatch")

def exporter_material(last: U32) -> List<&2,U32>:
  [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,
    16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,last]

def test_exporter(proof: Exporter.Proof, expected: List<&2,U32>) -> IO(Unit):
  match proof:
    case Exporter.ExporterProof{+key,+sig,+suffix}:
      do IO<Unit>:
        valid : Bool <- Exporter.verify(key,sig,suffix,exporter_material(31))
        replayed : Bool <- Exporter.verify(key,sig,suffix,exporter_material(30))
        encoded : Maybe<&1,List<&2,U32>> <- Exporter.sign(List.replicate(U32,32n,42),exporter_material(31))
        exporter_result(valid && Bool.not(replayed) && same_header(encoded,expected))
    case Exporter.MalformedExporterProof{}:
      IO.die(Unit,1,"relay exporter vector failed to decode")

def test_exporter_header(+expected: List<&2,U32>) -> IO(Unit):
  test_exporter(Exporter.decode(expected),expected)

def main() -> IO(Unit):
  do IO<Unit>:
    proof : Handshake.Auth <- IO.try(Handshake.Auth, Auth.sign_challenge(List.replicate(U32, 32n, 42), nonce()))
    test_proof(proof)
    test_exporter_header(exporter_bytes(String.to_list(
      "GX9rI-FshTLGq8g4-s1ep4m-DHaykgM0A5v6iz02jWFAQb98VXtFUshaBKOJKabtiBrsmgnPjpFdRpJqAzcy9jOAPc-kOvzLgXjeT9vCG8qx2yO7aDoF4n5vbE4kJbh2CBAREhMUFRYXGBkaGxwdHh8"))
    )
