import Base

def public_key(seed: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,List<&2,U32>>):
  import "./ed25519.c"

def sign(seed: List<&2,U32>, message: List<&2,U32>) ->
    IO(Result<&1,&1,U32 & String, List<&2,U32> & List<&2,U32>>):
  import "./ed25519.c"

def verify(public: List<&2,U32>, signature: List<&2,U32>, message: List<&2,U32>) -> IO(Bool):
  import "./ed25519.c"

# BEP 44 addresses an unsalted mutable item by SHA-1 of its public key.
def sha1_public_key(public: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,List<&2,U32>>):
  import "./ed25519.c"
