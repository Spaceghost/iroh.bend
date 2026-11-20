import Base
import ./relay_http.bend as Http
import ./relay_http_accept.bend as Accept

type UpgradeRead is Data:
  MoreHttp{state: Http.Reader}
  HttpRequestReady{request: Http.HttpRequest, pending: List<&2,U32>}
  HttpRejected{status: U32, version_header: Bool}
  WebSocketReady{version: U32, request: Http.HttpRequest, reply: List<&2,U32>, pending: List<&2,U32>}

def accepted(reply: Result<&1,&1,U32 & String,List<&2,U32>>, version: U32, request: Http.HttpRequest,
    pending: List<&2,U32>) -> UpgradeRead:
  match reply:
    case Done{bytes}:
      WebSocketReady{version,request,bytes,pending}
    case Fail{_}:
      HttpRejected{500,False{}}

def respond(decision: Http.UpgradeResult, request: Http.HttpRequest, pending: List<&2,U32>) -> IO(UpgradeRead):
  match decision:
    case Http.OrdinaryRequest{}:
      IO.pure(UpgradeRead,HttpRequestReady{request,pending})
    case Http.UpgradeRejected{status}:
      IO.pure(UpgradeRead,HttpRejected{status,False{}})
    case Http.UnsupportedWebSocketVersion{}:
      IO.pure(UpgradeRead,HttpRejected{400,True{}})
    case Http.UpgradeReady{+version,nonce}:
      do IO<UpgradeRead>:
        result : Result<&1,&1,U32 & String,List<&2,U32>> <- Accept.switching_protocols(version,nonce)
        return accepted(result,version,request,pending)

def finish(read: Http.RequestRead) -> IO(UpgradeRead):
  match read:
    case Http.AwaitingHead{state}:
      IO.pure(UpgradeRead,MoreHttp{state})
    case Http.BadRequestHead{status}:
      IO.pure(UpgradeRead,HttpRejected{status,False{}})
    case Http.HeadRead{+request,pending}:
      respond(Http.request_upgrade(request),request,pending)

# An upgrade returns both the exact HTTP fields and the unread wire bytes.
def receive(state: Http.Reader, bytes: List<&2,U32>) -> IO(UpgradeRead):
  finish(Http.receive(state,bytes))
