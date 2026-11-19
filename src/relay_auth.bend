import Base
import ./ed25519.bend as Ed
import ./handshake.bend as Handshake
import ./relay_challenge.bend as Digest

def result_to_proof(result: Result<&1,&1,U32 & String, List<&2,U32> & List<&2,U32>>)
  -> Result<&1,&1,U32 & String, Handshake.Auth>:
  match result:
    case Done{(key,sig)}:
      Done{Handshake.ClientProof{key,sig}}
    case Fail{error}:
      Fail{error}

def sign_challenge(seed: List<&2,U32>, nonce: List<&2,U32>) ->
    IO(Result<&1,&1,U32 & String, Handshake.Auth>):
  do IO<Result<&1,&1,U32 & String, Handshake.Auth>>:
    sealed : Result<&1,&1,U32 & String, List<&2,U32> & List<&2,U32>> <- Ed.sign(seed, Digest.derive(nonce))
    return result_to_proof(sealed)

def verify_challenge(proof: Handshake.Auth, nonce: List<&2,U32>) -> IO(Bool):
  match proof:
    case Handshake.ClientProof{key,sig}:
      Ed.verify(key, sig, Digest.derive(nonce))
    case _:
      IO.pure(Bool, False{})
