import Base

def sign(seed: List<&2,U32>, message: List<&2,U32>) ->
    IO(Result<&1,&1,U32 & String, List<&2,U32> & List<&2,U32>>):
  import "./ed25519.c"

def verify(public: List<&2,U32>, signature: List<&2,U32>, message: List<&2,U32>) -> IO(Bool):
  import "./ed25519.c"
