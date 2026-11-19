import Base
import ./discovery.bend as Dns
import ./pkarr.bend as Pkarr
import ./relay.bend as Bytes

# The relay base URL includes any route prefix, for example /pkarr.
def pkarr_http_request(relay: String, label: String, put: U32, body: List<&2,U32>, ms: U32)
    -> IO(Result<&1,&1,U32 & String,U32 & List<&2,U32>>):
  import "./pkarr_http.c"

def resolve_status(status: U32, body: List<&2,U32>, key: List<&2,U32>, successful: Bool)
    -> IO(Result<&1,&1,U32 & String,Pkarr.Verification>):
  match successful:
    case True{}:
      do IO<Result<&1,&1,U32 & String,Pkarr.Verification>>:
        proof : Pkarr.Verification <- Pkarr.verify_relay_body(key,body)
        return Done{proof}
    case False{}:
      IO.pure(Result<&1,&1,U32 & String,Pkarr.Verification>,Fail{(status,"Pkarr relay GET failed")})

def checked_resolution(response: Result<&1,&1,U32 & String,U32 & List<&2,U32>>,
    key: List<&2,U32>) -> IO(Result<&1,&1,U32 & String,Pkarr.Verification>):
  match response:
    case Done{(+status,body)}:
      resolve_status(status,body,key,U32.is_ge(status,200) && U32.is_lt(status,300))
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Pkarr.Verification>,Fail{error})

def resolve_label(label: Maybe<&2,String>, relay: String, key: List<&2,U32>, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Pkarr.Verification>):
  match label:
    case Some{z32}:
      do IO<Result<&1,&1,U32 & String,Pkarr.Verification>>:
        response : Result<&1,&1,U32 & String,U32 & List<&2,U32>> <-
          pkarr_http_request(relay,z32,0,[],ms)
        checked_resolution(response,key)
    case None{}:
      IO.pure(Result<&1,&1,U32 & String,Pkarr.Verification>,Fail{(1,"invalid Pkarr endpoint key")})

# Resolve verifies the signature against the requested endpoint. The caller
# sets freshness policy using the timestamp returned in Verified.
def resolve(relay: String, +key: List<&2,U32>, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Pkarr.Verification>):
  resolve_label(Dns.z32(key),relay,key,ms)

def publish_status(+status: U32, successful: Bool) -> Result<&1,&1,U32 & String,Unit>:
  match successful:
    case True{}:
      Done{Unit{}}
    case False{}:
      Fail{(status,"Pkarr relay PUT failed")}

def published(response: Result<&1,&1,U32 & String,U32 & List<&2,U32>>)
    -> Result<&1,&1,U32 & String,Unit>:
  match response:
    case Done{(+status,_)}:
      publish_status(status,U32.is_ge(status,200) && U32.is_lt(status,300))
    case Fail{error}:
      Fail{error}

def put_packet(relay: String, label: Maybe<&2,String>, envelope: Bytes.Split, proof: Pkarr.Verification,
    ms: U32) -> IO(Result<&1,&1,U32 & String,Unit>):
  match label envelope proof:
    case Some{z32} Bytes.Prefix{_,body} Pkarr.Verified{_,_}:
      do IO<Result<&1,&1,U32 & String,Unit>>:
        response : Result<&1,&1,U32 & String,U32 & List<&2,U32>> <-
          pkarr_http_request(relay,z32,1,body,ms)
        return published(response)
    case _ _ _:
      IO.pure(Result<&1,&1,U32 & String,Unit>,Fail{(1,"invalid signed Pkarr endpoint packet")})

# Publish an envelope produced by Pkarr.sign. Only the signature, timestamp,
# and DNS bytes go in the HTTP body. The key is in the path.
def publish(relay: String, +key: List<&2,U32>, +wire: List<&2,U32>, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Unit>):
  do IO<Result<&1,&1,U32 & String,Unit>>:
    proof : Pkarr.Verification <- Pkarr.verify(key,wire)
    put_packet(relay,Dns.z32(key),Bytes.split_peer(32n,wire,[]),proof,ms)
