import Base
import ./relay_server_socket.bend as Native
import ./relay_http.bend as Http
import ./relay_raw_http.bend as Raw
import ./relay_websocket.bend as Ws

type Stage is Data:
  AwaitHead{reader: Http.Reader}
  Upgraded{reader: Ws.Decoder, request: Maybe<&2,Http.HttpRequest>}

type Session is Data:
  Session{id: U32, stage: Stage}

type Buffered is Data:
  NoChunk{}
  Chunk{id: U32, bytes: List<&2,U32>}

type ServerSocket is Type:
  FramedSocket{socket: Native.ServerSocket}
  RawSocket{socket: Native.ServerSocket, sessions: List<&2,Session>, buffered: Buffered}

def native_bound(bound: Native.ServerSocket & U32) -> ServerSocket & U32:
  (socket,port) = bound
  (FramedSocket{socket},port)

def raw_bound(bound: Native.ServerSocket & U32) -> ServerSocket & U32:
  (socket,port) = bound
  (RawSocket{socket,[],NoChunk{}},port)

def relay_bind(host: String, port: U32, cert: String, key: String, raw: Bool)
    -> IO(Result<&1,&1,U32 & String,ServerSocket & U32>):
  match raw:
    case False{}:
      do IO<Result<&1,&1,U32 & String,ServerSocket & U32>>:
        bound : Result<&1,&1,U32 & String,Native.ServerSocket & U32> <- Native.relay_bind(host,port,cert,key)
        return Result.map(&1,&1,U32 & String,Native.ServerSocket & U32,ServerSocket & U32,native_bound,bound)
    case True{}:
      do IO<Result<&1,&1,U32 & String,ServerSocket & U32>>:
        bound : Result<&1,&1,U32 & String,Native.ServerSocket & U32> <- Native.relay_bind_raw(host,port,cert,key)
        return Result.map(&1,&1,U32 & String,Native.ServerSocket & U32,ServerSocket & U32,raw_bound,bound)

def choose_stage(before: Stage, rest: Unit -> Maybe<&2,Stage>, same: Bool) -> Maybe<&2,Stage>:
  match same:
    case True{}:
      Some{before}
    case False{}:
      rest(Unit{})

def lookup(sessions: List<&2,Session>, +id: U32) -> Maybe<&2,Stage>:
  match sessions:
    case Nil{}:
      None{}
    case Con{Session{key,stage},rest}:
      choose_stage(stage,_ => lookup(rest,id),U32.is_eq(key,id))

def session_id(session: Session) -> U32:
  Session{id,_} = session
  id

def omit(session: Session, rest: List<&2,Session>, matched: Bool) -> List<&2,Session>:
  match matched:
    case True{}:
      rest
    case False{}:
      Con{session,rest}

def drop(sessions: List<&2,Session>, +id: U32) -> List<&2,Session>:
  match sessions:
    case Nil{}:
      []
    case Con{+session,rest}:
      omit(session,drop(rest,id),U32.is_eq(session_id(session),id))

def replace(sessions: List<&2,Session>, +id: U32, stage: Stage) -> List<&2,Session>:
  Con{Session{id,stage},drop(sessions,id)}

def finish_chunk(sock: Native.ServerSocket, id: U32, sessions: List<&2,Session>)
    -> IO(ServerSocket & Native.SocketEvent):
  do IO<ServerSocket & Native.SocketEvent>:
    next : Native.ServerSocket <- Native.relay_raw_chunk_done(sock,id)
    return (RawSocket{next,sessions,NoChunk{}},Native.RelayIdle{})

def raw_close(sock: Native.ServerSocket, +id: U32, sessions: List<&2,Session>, flush: U32)
    -> IO(ServerSocket & Native.SocketEvent):
  do IO<ServerSocket & Native.SocketEvent>:
    next : Native.ServerSocket <- Native.relay_kick(sock,id,flush)
    return (RawSocket{next,drop(sessions,id),NoChunk{}},Native.RelayLeft{id})

def close_queued(result: Native.ServerSocket & Bool, id: U32, sessions: List<&2,Session>)
    -> IO(ServerSocket & Native.SocketEvent):
  match result:
    case (sock,True{}):
      raw_close(sock,id,sessions,1)
    case (sock,False{}):
      raw_close(sock,id,sessions,0)

def close_reply(sock: Native.ServerSocket, +id: U32, sessions: List<&2,Session>, reply: List<&2,U32>)
    -> IO(ServerSocket & Native.SocketEvent):
  do IO<ServerSocket & Native.SocketEvent>:
    queued : Native.ServerSocket & Bool <- Native.relay_queue(sock,id,reply)
    close_queued(queued,id,sessions)

def ws_close(sock: Native.ServerSocket, id: U32, sessions: List<&2,Session>,
    frame: Maybe<&2,List<&2,U32>>) -> IO(ServerSocket & Native.SocketEvent):
  match frame:
    case Some{reply}:
      close_reply(sock,id,sessions,reply)
    case None{}:
      raw_close(sock,id,sessions,0)

def raw_idle(sock: Native.ServerSocket, sessions: List<&2,Session>, buffered: Buffered)
    -> IO(ServerSocket & Native.SocketEvent):
  IO.pure(ServerSocket & Native.SocketEvent,(RawSocket{sock,sessions,buffered},Native.RelayIdle{}))

def pong_written(result: Native.ServerSocket & Bool, id: U32, sessions: List<&2,Session>,
    pending: List<&2,U32>) -> IO(ServerSocket & Native.SocketEvent):
  match result:
    case (sock,True{}):
      raw_idle(sock,sessions,Chunk{id,pending})
    case (sock,False{}):
      raw_close(sock,id,sessions,0)

def pong(sock: Native.ServerSocket, +id: U32, sessions: List<&2,Session>, pending: List<&2,U32>,
    encoded: Maybe<&2,List<&2,U32>>) -> IO(ServerSocket & Native.SocketEvent):
  match encoded:
    case Some{reply}:
      do IO<ServerSocket & Native.SocketEvent>:
        result : Native.ServerSocket & Bool <- Native.relay_queue(sock,id,reply)
        pong_written(result,id,sessions,pending)
    case None{}:
      raw_close(sock,id,sessions,0)

def frames(sock: Native.ServerSocket, +id: U32, sessions: List<&2,Session>,
    request: Maybe<&2,Http.HttpRequest>, read: Ws.Read) -> IO(ServerSocket & Native.SocketEvent):
  match read:
    case Ws.Waiting{reader}:
      finish_chunk(sock,id,replace(sessions,id,Upgraded{reader,request}))
    case Ws.Received{Ws.Binary{bytes},reader,pending}:
      IO.pure(ServerSocket & Native.SocketEvent,
        (RawSocket{sock,replace(sessions,id,Upgraded{reader,request}),Chunk{id,pending}},Native.RelayBytes{id,bytes}))
    case Ws.Received{Ws.Ping{bytes},reader,pending}:
      pong(sock,id,replace(sessions,id,Upgraded{reader,request}),pending,Ws.encode(Ws.Pong{bytes}))
    case Ws.Received{Ws.CloseFrame{bytes},_,_}:
      ws_close(sock,id,sessions,Ws.encode(Ws.CloseFrame{bytes}))
    case Ws.Received{_,reader,pending}:
      raw_idle(sock,replace(sessions,id,Upgraded{reader,request}),Chunk{id,pending})
    case Ws.Rejected{+status}:
      ws_close(sock,id,sessions,Ws.encode(Ws.CloseFrame{[U32.shrn(status,8n),U32.and(status,255)]}))

def upgrade_written(result: Native.ServerSocket & Bool, +id: U32, sessions: List<&2,Session>,
    version: U32, request: Http.HttpRequest, pending: List<&2,U32>) -> IO(ServerSocket & Native.SocketEvent):
  match result:
    case (sock,True{}):
      IO.pure(ServerSocket & Native.SocketEvent,
        (RawSocket{sock,replace(sessions,id,Upgraded{Ws.decoder(),Some{request}}),Chunk{id,pending}},
          Native.RelayJoined{id,version}))
    case (sock,False{}):
      raw_close(sock,id,sessions,0)

def rejection(status: U32, version: Bool) -> String:
  match status version:
    case 431 _:
      "HTTP/1.1 431 Request Header Fields Too Large\r\n"
    case 500 _:
      "HTTP/1.1 500 Internal Server Error\r\n"
    case _ True{}:
      "HTTP/1.1 400 Bad Request\r\nSec-WebSocket-Version: 13\r\n"
    case _ False{}:
      "HTTP/1.1 400 Bad Request\r\n"

def http(sock: Native.ServerSocket, +id: U32, sessions: List<&2,Session>, read: Raw.UpgradeRead)
    -> IO(ServerSocket & Native.SocketEvent):
  match read:
    case Raw.MoreHttp{reader}:
      finish_chunk(sock,id,replace(sessions,id,AwaitHead{reader}))
    case Raw.WebSocketReady{version,request,reply,pending}:
      do IO<ServerSocket & Native.SocketEvent>:
        sent : Native.ServerSocket & Bool <- Native.relay_queue(sock,id,reply)
        upgrade_written(sent,id,sessions,version,request,pending)
    case Raw.HttpRejected{status,version_header}:
      close_reply(sock,id,sessions,Http.ascii(rejection(status,version_header) ++
        "Connection: close\r\nContent-Length: 0\r\n\r\n"))
    case Raw.HttpRequestReady{_}:
      close_reply(sock,id,sessions,Http.ascii("HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))

def frame_limit(request: Maybe<&2,Http.HttpRequest>) -> U32:
  match request:
    case Some{_}:
      128
    case None{}:
      65544

def incoming(sock: Native.ServerSocket, +id: U32, sessions: List<&2,Session>, bytes: List<&2,U32>,
    stage: Maybe<&2,Stage>) -> IO(ServerSocket & Native.SocketEvent):
  match stage:
    case Some{AwaitHead{reader}}:
      do IO<ServerSocket & Native.SocketEvent>:
        read : Raw.UpgradeRead <- Raw.receive(reader,bytes)
        http(sock,id,sessions,read)
    case Some{Upgraded{reader,+request}}:
      frames(sock,id,sessions,request,Ws.receive(reader,bytes,frame_limit(request)))
    case None{}:
      finish_chunk(sock,id,sessions)

def native_event(result: Native.ServerSocket & Native.SocketEvent, +sessions: List<&2,Session>)
    -> IO(ServerSocket & Native.SocketEvent):
  match result:
    case (sock,Native.RelayJoined{id,0}):
      raw_idle(sock,replace(sessions,id,AwaitHead{Http.reader()}),NoChunk{})
    case (sock,Native.RelayBytes{+id,bytes}):
      incoming(sock,id,sessions,bytes,lookup(sessions,id))
    case (sock,Native.RelayLeft{+id}):
      IO.pure(ServerSocket & Native.SocketEvent,(RawSocket{sock,drop(sessions,id),NoChunk{}},Native.RelayLeft{id}))
    case (sock,event):
      IO.pure(ServerSocket & Native.SocketEvent,(RawSocket{sock,sessions,NoChunk{}},event))

def framed_event(result: Native.ServerSocket & Native.SocketEvent) -> ServerSocket & Native.SocketEvent:
  (sock,event) = result
  (FramedSocket{sock},event)

def relay_poll(transport: ServerSocket) -> IO(ServerSocket & Native.SocketEvent):
  match transport:
    case FramedSocket{sock}:
      do IO<ServerSocket & Native.SocketEvent>:
        event : Native.ServerSocket & Native.SocketEvent <- Native.relay_poll(sock)
        return framed_event(event)
    case RawSocket{sock,sessions,NoChunk{}}:
      do IO<ServerSocket & Native.SocketEvent>:
        event : Native.ServerSocket & Native.SocketEvent <- Native.relay_poll(sock)
        native_event(event,sessions)
    case RawSocket{sock,+sessions,Chunk{+id,pending}}:
      incoming(sock,id,sessions,pending,lookup(sessions,id))

def with_socket(transport: ServerSocket, action: Native.ServerSocket -> IO(Native.ServerSocket))
    -> IO(ServerSocket):
  match transport:
    case FramedSocket{sock}:
      do IO<ServerSocket>:
        next : Native.ServerSocket <- action(sock)
        return FramedSocket{next}
    case RawSocket{sock,sessions,buffered}:
      do IO<ServerSocket>:
        next : Native.ServerSocket <- action(sock)
        return RawSocket{next,sessions,buffered}

def relay_enable_request_details(transport: ServerSocket) -> IO(ServerSocket):
  with_socket(transport,sock => Native.relay_enable_request_details(sock))

def relay_resume_rx(transport: ServerSocket, id: U32) -> IO(ServerSocket):
  with_socket(transport,sock => Native.relay_resume_rx(sock,id))

def relay_meter_challenge(transport: ServerSocket, id: U32, enabled: Bool) -> IO(ServerSocket):
  with_socket(transport,sock => Native.relay_meter_challenge(sock,id,enabled))

def relay_reconfigure_rx(transport: ServerSocket, enabled: Bool) -> IO(ServerSocket):
  with_socket(transport,sock => Native.relay_reconfigure_rx(sock,enabled))

def relay_stop(transport: ServerSocket) -> IO(Unit):
  match transport:
    case FramedSocket{sock}:
      Native.relay_stop(sock)
    case RawSocket{sock,_,_}:
      Native.relay_stop(sock)

def carry_framed(-A: Type, result: Native.ServerSocket & A) -> ServerSocket & A:
  (sock,value) = result
  (FramedSocket{sock},value)

def carry_raw(-A: Type, result: Native.ServerSocket & A, sessions: List<&2,Session>, buffered: Buffered)
    -> ServerSocket & A:
  (sock,value) = result
  (RawSocket{sock,sessions,buffered},value)

def native_queue(sock: Native.ServerSocket, id: U32, encoded: Maybe<&2,List<&2,U32>>)
    -> IO(Native.ServerSocket & Bool):
  match encoded:
    case Some{bytes}:
      Native.relay_queue(sock,id,bytes)
    case None{}:
      IO.pure(Native.ServerSocket & Bool,(sock,False{}))

def relay_queue(transport: ServerSocket, id: U32, bytes: List<&2,U32>) -> IO(ServerSocket & Bool):
  match transport:
    case FramedSocket{sock}:
      do IO<ServerSocket & Bool>:
        result : Native.ServerSocket & Bool <- Native.relay_queue(sock,id,bytes)
        return carry_framed(Bool,result)
    case RawSocket{sock,sessions,buffered}:
      do IO<ServerSocket & Bool>:
        result : Native.ServerSocket & Bool <- native_queue(sock,id,Ws.encode(Ws.Binary{bytes}))
        return carry_raw(Bool,result,sessions,buffered)

def relay_export_keying_material(transport: ServerSocket, id: U32, key: List<&2,U32>)
    -> IO(ServerSocket & Maybe<&1,List<&2,U32>>):
  match transport:
    case FramedSocket{sock}:
      do IO<ServerSocket & Maybe<&1,List<&2,U32>>>:
        result : Native.ServerSocket & Maybe<&1,List<&2,U32>> <- Native.relay_export_keying_material(sock,id,key)
        return carry_framed(Maybe<&1,List<&2,U32>>,result)
    case RawSocket{sock,sessions,buffered}:
      do IO<ServerSocket & Maybe<&1,List<&2,U32>>>:
        result : Native.ServerSocket & Maybe<&1,List<&2,U32>> <- Native.relay_export_keying_material(sock,id,key)
        return carry_raw(Maybe<&1,List<&2,U32>>,result,sessions,buffered)

def auth_value(fields: List<&2,List<&2,U32>>) -> Maybe<&1,List<&2,U32>>:
  match fields:
    case Nil{}:
      None{}
    case [proof]:
      Some{proof}
    case _:
      Some{[]}

def raw_auth(stage: Maybe<&2,Stage>) -> Maybe<&1,List<&2,U32>>:
  match stage:
    case Some{Upgraded{_,Some{Http.RequestHead{_,_,_,fields}}}}:
      auth_value(Http.values(fields,Http.ascii("x-iroh-relay-client-auth-v1")))
    case _:
      None{}

def relay_client_auth_header(transport: ServerSocket, id: U32)
    -> IO(ServerSocket & Maybe<&1,List<&2,U32>>):
  match transport:
    case FramedSocket{sock}:
      do IO<ServerSocket & Maybe<&1,List<&2,U32>>>:
        result : Native.ServerSocket & Maybe<&1,List<&2,U32>> <- Native.relay_client_auth_header(sock,id)
        return carry_framed(Maybe<&1,List<&2,U32>>,result)
    case RawSocket{sock,+sessions,buffered}:
      IO.pure(ServerSocket & Maybe<&1,List<&2,U32>>,
        (RawSocket{sock,sessions,buffered},raw_auth(lookup(sessions,id))))

def clear_admission(sessions: List<&2,Session>, id: U32, stage: Maybe<&2,Stage>) -> List<&2,Session>:
  match stage:
    case Some{Upgraded{reader,_}}:
      replace(sessions,id,Upgraded{reader,None{}})
    case _:
      sessions

def relay_authorized_with_meter(transport: ServerSocket, +id: U32, enabled: Bool) -> IO(ServerSocket):
  match transport:
    case FramedSocket{sock}:
      with_socket(FramedSocket{sock},net => Native.relay_authorized_with_meter(net,id,enabled))
    case RawSocket{sock,+sessions,buffered}:
      do IO<ServerSocket>:
        next : Native.ServerSocket <- Native.relay_authorized_with_meter(sock,id,enabled)
        return RawSocket{next,clear_admission(sessions,id,lookup(sessions,id)),buffered}

def close_mode(stage: Maybe<&2,Stage>, requested: U32) -> U32:
  match stage:
    # The 101 may still be queued when the request's exporter proof is rejected.
    case Some{Upgraded{_,Some{_}}}:
      1
    case _:
      requested

def relay_kick(transport: ServerSocket, +id: U32, flush: U32) -> IO(ServerSocket):
  match transport:
    case FramedSocket{sock}:
      with_socket(FramedSocket{sock},net => Native.relay_kick(net,id,flush))
    case RawSocket{sock,+sessions,buffered}:
      do IO<ServerSocket>:
        next : Native.ServerSocket <- Native.relay_kick(sock,id,close_mode(lookup(sessions,id),flush))
        return RawSocket{next,drop(sessions,id),buffered}

def choose_header(+name: List<&2,U32>, fields: List<&2,Http.HttpField>,
    rest: List<&2,Native.RequestHeader>, duplicate: Bool) -> List<&2,Native.RequestHeader>:
  match duplicate:
    case True{}:
      rest
    case False{}:
      Con{Native.HeaderField{name,Native.HeaderValues{Http.values(fields,name)}},rest}

def seen_header(names: List<&2,List<&2,U32>>, +name: List<&2,U32>) -> Bool:
  match names:
    case Nil{}:
      False{}
    case Con{key,rest}:
      Http.equal(key,name) || seen_header(rest,name)

def request_headers(rest: List<&2,Http.HttpField>, +all: List<&2,Http.HttpField>, +seen: List<&2,List<&2,U32>>)
    -> List<&2,Native.RequestHeader>:
  match rest:
    case Con{Http.HttpFieldValue{+name,_},tail}:
      choose_header(name,all,request_headers(tail,all,Con{name,seen}),
        seen_header(seen,name))
    case Nil{}:
      []

def nibble(+byte: U32, digit: Bool, upper: Bool, lower: Bool) -> U32:
  match digit upper lower:
    case True{} _ _:
      U32.sub(byte,48)
    case _ True{} _:
      U32.sub(byte,55)
    case _ _ True{}:
      U32.sub(byte,87)
    case _ _ _:
      16

def hex(+byte: U32) -> U32:
  nibble(byte,U32.is_ge(byte,48) && U32.is_le(byte,57),U32.is_ge(byte,65) && U32.is_le(byte,70),
    U32.is_ge(byte,97) && U32.is_le(byte,102))

def append_escape(a: U32, b: U32, output: List<&2,U32>, decoded: U32, valid: Bool) -> List<&2,U32>:
  match valid:
    case True{}:
      Con{decoded,output}
    case False{}:
      Con{b,Con{a,Con{37,output}}}

def escaped(+a: U32, +b: U32, output: List<&2,U32>, in_value: Bool) -> List<&2,U32>:
  +hi = hex(a)
  +lo = hex(b)
  +decoded = U32.add(U32.shln(hi,4n),lo)
  append_escape(a,b,output,decoded,U32.is_lt(hi,16) && U32.is_lt(lo,16) &&
    (in_value || Bool.not(U32.is_eq(decoded,61))))

# Split on literal ampersands. Only a literal equals can delimit a name
# from its value, including when a policy consumes the flattened field.
def query_pieces(input: List<&2,U32>, output: List<&2,U32>, complete: List<&2,List<&2,U32>>, +in_value: Bool)
    -> List<&2,List<&2,U32>>:
  match input:
    case Nil{}:
      List.reverse(&2,List<&2,U32>,Con{List.reverse(&2,U32,output),complete})
    case Con{38,rest}:
      query_pieces(rest,[],Con{List.reverse(&2,U32,output),complete},False{})
    case Con{61,rest}:
      query_pieces(rest,Con{61,output},complete,True{})
    case Con{43,rest}:
      query_pieces(rest,Con{32,output},complete,in_value)
    case Con{37,Con{38,rest}}:
      query_pieces(rest,[],Con{List.reverse(&2,U32,Con{37,output}),complete},False{})
    case Con{37,Con{a,Con{38,rest}}}:
      query_pieces(rest,[],Con{List.reverse(&2,U32,Con{a,Con{37,output}}),complete},False{})
    case Con{37,Con{a,Con{b,rest}}}:
      query_pieces(rest,escaped(a,b,output,in_value),complete,in_value)
    case Con{b,rest}:
      query_pieces(rest,Con{b,output},complete,in_value)

def query_arguments(query: Maybe<&2,List<&2,U32>>) -> List<&2,List<&2,U32>>:
  match query:
    case Some{raw}:
      query_pieces(raw,[],[],False{})
    case None{}:
      []

def raw_details(stage: Maybe<&2,Stage>) -> Native.RequestDetails:
  match stage:
    case Some{Upgraded{_,Some{Http.RequestHead{_,+target,_,+fields}}}}:
      Native.Details{Http.path(target),Native.FieldsWithHeaders{Http.values(fields,Http.ascii("authorization")),
        query_arguments(Http.query(target)),request_headers(fields,fields,[])}}
    case _:
      Native.MissingDetails{}

def relay_request_details(transport: ServerSocket, id: U32) -> IO(ServerSocket & Native.RequestDetails):
  match transport:
    case FramedSocket{sock}:
      do IO<ServerSocket & Native.RequestDetails>:
        result : Native.ServerSocket & Native.RequestDetails <- Native.relay_request_details(sock,id)
        return carry_framed(Native.RequestDetails,result)
    case RawSocket{sock,+sessions,buffered}:
      IO.pure(ServerSocket & Native.RequestDetails,(RawSocket{sock,sessions,buffered},raw_details(lookup(sessions,id))))
