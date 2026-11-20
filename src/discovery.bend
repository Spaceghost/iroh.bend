import Base
import ./relay.bend as Bytes

# Iroh DNS publishes one endpoint's data as TXT at _iroh.<z32 key>.<origin>.
# TXT values retain their UTF-8 bytes. Address/URL parsing belongs to dialing.
type Attribute is Data:
  RelayUrl{value: List<&2,U32>}
  Address{value: List<&2,U32>}
  UserData{value: List<&2,U32>}

def at(+index: Nat, chars: List<&2,Char>) -> Char:
  match index chars:
    case 0n Con{c,_}:
      c
    case 1n+k Con{_,tail}:
      at(k,tail)
    case _ _:
      Chr{0}

def digit(n: U32) -> Char:
  at(U32.to_nat(n), String.to_list("ybndrfg8ejkmcpqxot1uwisza345h769"))

def bits_mask(n: U32) -> U32:
  U32.sub(U32.shln(1,U32.to_nat(n)),1)

def padded_digit(word: U32, width: U32, output: List<&2,Char>, present: Bool) -> List<&2,Char>:
  match present:
    case False{}:
      output
    case True{}:
      Con{digit(U32.shln(word,U32.to_nat(U32.sub(5,width)))),output}

def base32(+fuel: Nat, input: List<&2,U32>, +word: U32, +width: U32, output: List<&2,Char>,
    emit: Bool) -> List<&2,Char>:
  match fuel input emit:
    case 1n+k _ True{}:
      +left = U32.sub(width,5)
      base32(k,input,U32.and(word,bits_mask(left)),left,
        Con{digit(U32.shrn(word,U32.to_nat(left))),output},U32.is_ge(left,5))
    case 1n+k Con{byte,rest} False{}:
      base32(k,rest,U32.or(U32.shln(word,8n),byte),U32.add(width,8),output,True{})
    case _ _ _:
      padded_digit(word,width,output,U32.is_gt(width,0))

def endpoint_label(key: List<&2,U32>, measured: Bytes.Size) -> Maybe<&2,String>:
  match measured:
    case Bytes.Length{32}:
      Some{String.from_list(List.reverse(&2,Char,base32(85n,key,0,0,[],False{})))}
    case _:
      None{}

def z32(+key: List<&2,U32>) -> Maybe<&2,String>:
  endpoint_label(key,Bytes.measure_limited(key,32))

def named(label: Maybe<&2,String>, origin: String) -> Maybe<&2,String>:
  match label:
    case None{}:
      None{}
    case Some{middle}:
      Some{String.append("_iroh.",String.append(middle,String.append(".",origin)))}

def name(key: List<&2,U32>, origin: String) -> Maybe<&2,String>:
  named(z32(key),origin)

def chars_to_bytes(chars: List<&2,Char>) -> List<&2,U32>:
  match chars:
    case Nil{}:
      []
    case Con{c,rest}:
      Con{Char.to_u32(c),chars_to_bytes(rest)}

def keyword(k: String) -> List<&2,U32>:
  chars_to_bytes(String.to_list(k))

def bytes_eq(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(x,y) && bytes_eq(xs,ys)
    case _ _:
      False{}

def attribute(value: List<&2,U32>, relay: Bool, addr: Bool, user: Bool) -> Maybe<&2,Attribute>:
  match relay addr user:
    case True{} _ _:
      Some{RelayUrl{value}}
    case _ True{} _:
      Some{Address{value}}
    case _ _ True{}:
      Some{UserData{value}}
    case _ _ _:
      None{}

def attribute_key(+key: List<&2,U32>, value: List<&2,U32>) -> Maybe<&2,Attribute>:
  attribute(value,bytes_eq(key,keyword("relay")),bytes_eq(key,keyword("addr")),
    bytes_eq(key,keyword("user-data")))

def take_value(bytes: List<&2,U32>) -> List<&2,U32>:
  match bytes:
    case Con{61,_}:
      []
    case Con{byte,rest}:
      Con{byte,take_value(rest)}
    case Nil{}:
      []

# Match upstream's split('=') behavior. The text after a second '=' is ignored.
def split_attribute(bytes: List<&2,U32>, reversed: List<&2,U32>) -> Maybe<&2,Attribute>:
  match bytes:
    case Nil{}:
      None{}
    case Con{61,rest}:
      attribute_key(List.reverse(&2,U32,reversed),take_value(rest))
    case Con{byte,rest}:
      split_attribute(rest,Con{byte,reversed})

def txt_checked(bytes: List<&2,U32>, valid: Bool) -> Maybe<&2,Attribute>:
  match valid:
    case True{}:
      split_attribute(bytes,[])
    case False{}:
      None{}

def txt(+bytes: List<&2,U32>) -> Maybe<&2,Attribute>:
  txt_checked(bytes,Bytes.utf8_scan(bytes,Bytes.Lead{}))

type Query is Data:
  TxtQuery{id: U32, owner: List<&2,U32>, wire: List<&2,U32>}
  InvalidQuery{}

def encode_label_parts(label: List<&2,U32>, tails: Maybe<&2,List<&2,U32>>, size: Bytes.Size)
    -> Maybe<&2,List<&2,U32>>:
  match tails size:
    case Some{rest} Bytes.Length{0}:
      None{}
    case Some{rest} Bytes.Length{n}:
      Some{Con{n,List.append(&2,U32,label,rest)}}
    case _ _:
      None{}

def last_label(+bytes: List<&2,U32>, empty: Bool) -> Maybe<&2,List<&2,U32>>:
  match empty:
    case True{}:
      Some{[0]}
    case False{}:
      encode_label_parts(bytes,Some{[0]},Bytes.measure_limited(bytes,63))

def labels(parts: List<&2,String>) -> Maybe<&2,List<&2,U32>>:
  match parts:
    case Nil{}:
      Some{[0]}
    case Con{+part,Nil{}}:
      last_label(keyword(part),String.eq(part,""))
    case Con{part,rest}:
      +bytes = keyword(part)
      encode_label_parts(bytes,labels(rest),Bytes.measure_limited(bytes,63))

def query_sized(+id: U32, +owner: List<&2,U32>, size: Bytes.Size) -> Query:
  match size:
    case Bytes.Length{_}:
      TxtQuery{id,owner,List.append(&2,U32,[U32.shrn(id,8n),U32.and(id,255),1,0,0,1,0,0,0,0,0,0],
        List.append(&2,U32,owner,[0,16,0,1]))}
    case _:
      InvalidQuery{}

def query_packet(+id: U32, encoded: Maybe<&2,List<&2,U32>>) -> Query:
  match encoded:
    case None{}:
      InvalidQuery{}
    case Some{+owner}:
      query_sized(id,owner,Bytes.measure_limited(owner,255))

def query_name(id: U32, host: Maybe<&2,String>) -> Query:
  match host:
    case None{}:
      InvalidQuery{}
    case Some{domain}:
      query_packet(U32.and(id,65535),labels(String.split(domain,Chr{46})))

def query(id: U32, key: List<&2,U32>, origin: String) -> Query:
  query_name(id,name(key,origin))

type Reply is Data:
  Found{records: List<&2,Attribute>}
  Truncated{}
  DnsError{rcode: U32}
  InvalidReply{}

def be16(a: U32, b: U32) -> U32:
  U32.or(U32.shln(a,8n),b)

def lower_ascii(+b: U32) -> U32:
  U32.add(b,U32.mul(32,Bool.to_u32(U32.is_ge(b,65) && U32.is_le(b,90))))

def dns_equal(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(lower_ascii(x),lower_ascii(y)) && dns_equal(xs,ys)
    case _ _:
      False{}

type DnsName is Data:
  ReadName{owner: List<&2,U32>, rest: List<&2,U32>, offset: U32}
  BadName{}

type NameStep is Data:
  Recorded{b: U32, left: U32, rest: List<&2,U32>}
  Root{rest: List<&2,U32>}
  Pointer{target: U32, rest: List<&2,U32>}
  BadStep{}

def label_byte(+b: U32, rest: List<&2,U32>, ordinary: Bool, pointer: Bool) -> NameStep:
  match rest ordinary pointer:
    case _ True{} _:
      Recorded{b,b,rest}
    case Con{low,tail} False{} True{}:
      Pointer{be16(U32.and(b,63),low),tail}
    case _ _ _:
      BadStep{}

def classify_name(bytes: List<&2,U32>, +left: U32) -> NameStep:
  match bytes left:
    case Con{0,tail} 0:
      Root{tail}
    case Con{+b,tail} 0:
      label_byte(b,tail,U32.is_lt(b,64),U32.is_ge(b,192))
    case Con{b,tail} _:
      Recorded{b,U32.sub(left,1),tail}
    case _ _:
      BadStep{}

def drop(+count: Nat, bytes: List<&2,U32>) -> List<&2,U32>:
  match count bytes:
    case 0n _:
      bytes
    case 1n+k Con{_,tail}:
      drop(k,tail)
    case _ _:
      []

type Resume is Data:
  Sequential{}
  ResumeAt{rest: List<&2,U32>, offset: U32}

def save(at: Resume, rest: List<&2,U32>, offset: U32) -> Resume:
  match at:
    case Sequential{}:
      ResumeAt{rest,offset}
    case _:
      at

def name_end(owner: List<&2,U32>, rest: List<&2,U32>, offset: U32, resume: Resume) -> DnsName:
  match resume:
    case Sequential{}:
      ReadName{owner,rest,offset}
    case ResumeAt{tail,at}:
      ReadName{owner,tail,at}

def pointer_step(+packet: List<&2,U32>, +target: U32, backward: Bool) -> NameStep:
  match backward:
    case False{}:
      BadStep{}
    case True{}:
      classify_name(drop(U32.to_nat(target),packet),0)

# A name is at most 255 wire bytes. Backward-only compression pointers
# consume the same finite scan budget as literal label bytes.
def walk_name(+budget: Nat, step: NameStep, +packet: List<&2,U32>, +position: U32,
    reversed: List<&2,U32>, resume: Resume) -> DnsName:
  match budget step:
    case _ Root{tail}:
      name_end(List.reverse(&2,U32,Con{0,reversed}),tail,U32.inc(position),resume)
    case 1n+k Recorded{b,left,tail}:
      walk_name(k,classify_name(tail,left),packet,U32.inc(position),Con{b,reversed},resume)
    case 1n+k Pointer{+target,tail}:
      walk_name(k,pointer_step(packet,target,U32.is_lt(target,position)),packet,target,
        reversed,save(resume,tail,U32.add(position,2)))
    case _ _:
      BadName{}

def read_name(bytes: List<&2,U32>, packet: List<&2,U32>, offset: U32) -> DnsName:
  walk_name(254n,classify_name(bytes,0),packet,offset,[],Sequential{})

type Text is Data:
  TextBytes{bytes: List<&2,U32>}
  BadText{}

# DNS TXT RDATA is an ordered sequence of length-prefixed strings.
def unpack_txt(+fuel: Nat, encoded: List<&2,U32>, reversed: List<&2,U32>, +need: U32) -> Text:
  match fuel encoded need:
    case _ Nil{} 0:
      TextBytes{List.reverse(&2,U32,reversed)}
    case 1n+k Con{n,rest} 0:
      unpack_txt(k,rest,reversed,n)
    case 1n+k Con{b,rest} _:
      unpack_txt(k,rest,Con{b,reversed},U32.sub(need,1))
    case _ _ _:
      BadText{}

type Record is Data:
  Resource{value: Maybe<&2,Attribute>, rest: List<&2,U32>, offset: U32}
  BadRecord{}

def record_attr(value: Maybe<&2,Attribute>, rest: List<&2,U32>, offset: U32) -> Record:
  match value:
    case None{}:
      BadRecord{}
    case _:
      Resource{value,rest,offset}

def record_txt(text: Text, tail: List<&2,U32>, offset: U32) -> Record:
  match text:
    case TextBytes{data}:
      record_attr(txt(data),tail,offset)
    case BadText{}:
      BadRecord{}

def record_payload(body: Bytes.Split, offset: U32, is_txt: Bool) -> Record:
  match body is_txt:
    case Bytes.Prefix{data,rest} True{}:
      record_txt(unpack_txt(4096n,data,[],0),rest,offset)
    case Bytes.Prefix{_,rest} False{}:
      Resource{None{},rest,offset}
    case Bytes.ShortPrefix{} _:
      BadRecord{}

def record_body(rest: List<&2,U32>, +offset: U32, +owner_matches: Bool) -> Record:
  match rest:
    case Con{th,Con{tl,Con{ch,Con{cl,Con{_,Con{_,Con{_,Con{_,Con{lh,Con{ll,tail}}}}}}}}}}:
      +size = be16(lh,ll)
      record_payload(Bytes.split_peer(U32.to_nat(size),tail,[]),U32.add(U32.add(offset,10),size),
        owner_matches && U32.is_eq(be16(th,tl),16) && U32.is_eq(be16(ch,cl),1))
    case _:
      BadRecord{}

def answer(name: DnsName, expected: List<&2,U32>) -> Record:
  match name:
    case ReadName{owner,rest,offset}:
      record_body(rest,offset,dns_equal(expected,owner))
    case BadName{}:
      BadRecord{}

def collect(items: Maybe<&2,Attribute>, acc: List<&2,Attribute>) -> List<&2,Attribute>:
  match items:
    case Some{attr}:
      Con{attr,acc}
    case None{}:
      acc

def answers(+count: Nat, first: Record, +packet: List<&2,U32>, +expected: List<&2,U32>,
    acc: List<&2,Attribute>) -> Reply:
  match count first:
    case 0n _:
      Found{List.reverse(&2,Attribute,acc)}
    case 1n+0n Resource{value,_,_}:
      Found{List.reverse(&2,Attribute,collect(value,acc))}
    case 1n+k Resource{value,rest,offset}:
      answers(k,answer(read_name(rest,packet,offset),expected),packet,expected,collect(value,acc))
    case _ BadRecord{}:
      InvalidReply{}

def answer_status(rest: List<&2,U32>, offset: U32, +packet: List<&2,U32>,
    +expected: List<&2,U32>, count: U32, +rcode: U32) -> Reply:
  match rcode:
    case 0:
      answers(U32.to_nat(count),answer(read_name(rest,packet,offset),expected),packet,expected,[])
    case _:
      DnsError{rcode}

def question_body(rest: List<&2,U32>, offset: U32, packet: List<&2,U32>, expected: List<&2,U32>,
    count: U32, rcode: U32, matched: Bool, tc: Bool) -> Reply:
  match rest matched tc:
    case Con{0,Con{16,Con{0,Con{1,_}}}} True{} True{}:
      Truncated{}
    case Con{0,Con{16,Con{0,Con{1,records}}}} True{} False{}:
      answer_status(records,U32.add(offset,4),packet,expected,count,rcode)
    case _ _ _:
      InvalidReply{}

def response_question(question: DnsName, +expected: List<&2,U32>, packet: List<&2,U32>,
    count: U32, rcode: U32, tc: Bool) -> Reply:
  match question:
    case ReadName{owner,rest,offset}:
      question_body(rest,offset,packet,expected,count,rcode,dns_equal(expected,owner),tc)
    case BadName{}:
      InvalidReply{}

def response_header(+packet: List<&2,U32>, expected: List<&2,U32>, q: List<&2,U32>, count: U32,
    +flags: U32, allowed: Bool) -> Reply:
  match allowed:
    case False{}:
      InvalidReply{}
    case True{}:
      response_question(read_name(q,packet,12),expected,packet,count,U32.and(flags,15),
        U32.is_gt(U32.and(flags,512),0))

def header(+packet: List<&2,U32>, id: U32, expected: List<&2,U32>) -> Reply:
  match packet:
    case Con{ih,Con{il,Con{+fh,Con{fl,Con{0,Con{1,Con{ah,Con{al,Con{_,Con{_,Con{_,Con{_,q}}}}}}}}}}}}:
      response_header(packet,expected,q,be16(ah,al),be16(fh,fl),
        U32.is_eq(be16(ih,il),id) && U32.is_eq(U32.and(fh,248),128))
    case _:
      InvalidReply{}

def response_checked(+packet: List<&2,U32>, request: Query, size: Bytes.Size) -> Reply:
  match request size:
    case TxtQuery{id,owner,_} Bytes.Length{_}:
      header(packet,id,owner)
    case _ _:
      InvalidReply{}

def response(request: Query, +packet: List<&2,U32>) -> Reply:
  response_checked(packet,request,Bytes.measure_limited(packet,4096))

# The caller provides an IPv4 recursive resolver. Match the source, DNS ID,
# question name, type and class before exposing any records.
def checked_source(request: Query, data: List<&2,U32>, matched: Bool) -> Reply:
  match matched:
    case True{}:
      response(request,data)
    case False{}:
      InvalidReply{}

def recv_result(answer: Poll<&1,&1,Result<&1,&1,U32 & String,String & U32 & List<&2,U32>>,Unit>,
    request: Query, +resolver: String, +port: U32) -> Result<&1,&1,U32 & String,Reply>:
  match answer:
    case Ready{Done{(from,from_port,data)}}:
      Done{checked_source(request,data,String.eq(resolver,from) && U32.is_eq(port,from_port))}
    case Ready{Fail{error}}:
      Fail{error}
    case Wait{_}:
      Fail{(1,"DNS lookup timed out")}

def count_bytes(bytes: List<&2,U32>) -> U32:
  U32.from_nat(List.length(&2,U32,bytes))

type TcpChunk is Data:
  Chunk{bytes: List<&2,U32>}
  ReadFailed{code: U32, message: String}

type WaitMode is Data:
  TimedWait{}
  StopOnClose{stop: Chan(Unit)}

def ReadReply() -> Type:
  Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>

def UdpReply() -> Type:
  Result<&1,&1,U32 & String,String & U32 & List<&2,U32>>

def WriteReply() -> Type:
  Result<&1,&1,(U32 & String) & List<&2,U32>,Unit>

def SocketPoll(-R: Type, -P: Type) -> Type:
  Socket & Poll<&1,&1,R,P>

def SocketOp(-C: Data, -R: Type, -P: Type) -> Type:
  C -> Socket -> P -> U32 -> IO(SocketPoll(R,P))

def resume_wait(-R: Type, -P: Type, event: Poll<&1,&1,Maybe<&1,Unit>,Unit>, left: Nat,
    socket: Socket, pending: P, retry: Socket -> P -> U32 -> IO(SocketPoll(R,P))) -> IO(SocketPoll(R,P)):
  match event left:
    case Wait{_} 1n+k:
      retry(socket,pending,U32.from_nat(1n+k))
    case _ _:
      IO.pure(SocketPoll(R,P),(socket,Wait{pending}))

def after_wait(-R: Type, -P: Type, outcome: SocketPoll(R,P), stop: Chan(Unit), deadline: Nat,
    retry: Socket -> P -> U32 -> IO(SocketPoll(R,P))) -> IO(SocketPoll(R,P)):
  match outcome:
    case (socket,Wait{pending}):
      do IO<SocketPoll(R,P)>:
        event : Poll<&1,&1,Maybe<&1,Unit>,Unit> <- Chan.try_recv(Unit,stop,0)
        now : Nat <- IO.now()
        resume_wait(R,P,event,Nat.sub(deadline,now),socket,pending,retry)
    case _:
      IO.pure(SocketPoll(R,P),outcome)

# Bend socket operations return the socket and the unsent suffix when they time
# out. Keep one deadline across slices so cancellation can interrupt any wait.
@unsafe def watch_socket(~C: Data, ~R: Type, ~P: Type, ~op: SocketOp(C,R,P), +context: C,
    socket: Socket, pending: P, ms: U32, +deadline: Nat, +stop: Chan(Unit)) -> IO(SocketPoll(R,P)):
  do IO<SocketPoll(R,P)>:
    outcome : SocketPoll(R,P) <- op(context,socket,pending,U32.min(ms,20))
    after_wait(R,P,outcome,stop,deadline,sock => rest => left =>
      watch_socket(~C,~R,~P,~op,context,sock,rest,left,deadline,stop))

def wait_socket(~C: Data, ~R: Type, ~P: Type, ~op: SocketOp(C,R,P), mode: WaitMode, context: C,
    socket: Socket, pending: P, +ms: U32) -> IO(SocketPoll(R,P)):
  match mode:
    case TimedWait{}:
      op(context,socket,pending,ms)
    case StopOnClose{stop}:
      do IO<SocketPoll(R,P)>:
        now : Nat <- IO.now()
        watch_socket(~C,~R,~P,~op,context,socket,pending,ms,Nat.add(now,U32.to_nat(ms)),stop)

def tcp_receive(size: U32, socket: Socket, pending: Unit, ms: U32) -> IO(SocketPoll(ReadReply(),Unit)):
  TCP.try_recv_bytes(socket,size,ms)

def udp_receive(size: U32, socket: Socket, pending: Unit, ms: U32) -> IO(SocketPoll(UdpReply(),Unit)):
  UDP.try_recv_bytes_from(socket,size,ms)

def tcp_write(context: Unit, socket: Socket, pending: List<&2,U32>, ms: U32)
    -> IO(SocketPoll(WriteReply(),List<&2,U32>)):
  TCP.try_send_bytes(socket,pending,ms)

type UdpTarget is Data:
  UdpTarget{host: String, port: U32}

def udp_write(target: UdpTarget, socket: Socket, pending: List<&2,U32>, ms: U32)
    -> IO(SocketPoll(WriteReply(),List<&2,U32>)):
  UdpTarget{host,port} = target
  UDP.try_send_bytes_to(socket,host,port,pending,ms)

def wrap_sent(sent: Socket & WriteReply()) -> SocketPoll(WriteReply(),List<&2,U32>):
  (socket,result) = sent
  (socket,Ready{result})

def send_query(mode: WaitMode, +host: String, +port: U32, socket: Socket, data: List<&2,U32>, ms: U32)
    -> IO(SocketPoll(WriteReply(),List<&2,U32>)):
  match mode:
    case TimedWait{}:
      do IO<SocketPoll(WriteReply(),List<&2,U32>)>:
        sent : Socket & WriteReply() <- UDP.send_bytes_to(socket,host,port,data)
        return wrap_sent(sent)
    case StopOnClose{_}:
      wait_socket(~UdpTarget,~WriteReply(),~List<&2,U32>,~udp_write,mode,UdpTarget{host,port},socket,data,ms)

def OpenTcp() -> Type:
  String -> U32 -> U32 -> IO(Result<&1,&1,U32 & String,Socket>)

def read_more(outcome: Socket & Poll<&1,&1,Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>,Unit>,
    continue: Socket -> List<&2,U32> -> IO(Socket & TcpChunk)) -> IO(Socket & TcpChunk):
  match outcome:
    case (socket,Ready{Done{Some{Con{byte,tail}}}}):
      continue(socket,Con{byte,tail})
    case (socket,Ready{Done{_}}):
      IO.pure(Socket & TcpChunk,(socket,ReadFailed{1,"DNS TCP reply ended early"}))
    case (socket,Ready{Fail{(code,message)}}):
      IO.pure(Socket & TcpChunk,(socket,ReadFailed{code,message}))
    case (socket,Wait{_}):
      IO.pure(Socket & TcpChunk,(socket,ReadFailed{1,"DNS TCP read timed out"}))

def read_exact(+fuel: Nat, socket: Socket, +left: U32, +ms: U32, reversed: List<&2,U32>, +mode: WaitMode)
    -> IO(Socket & TcpChunk):
  match fuel left:
    case _ 0:
      IO.pure(Socket & TcpChunk,(socket,Chunk{List.reverse(&2,U32,reversed)}))
    case 1n+k _:
      do IO<Socket & TcpChunk>:
        received : Socket & Poll<&1,&1,Result<&1,&1,U32 & String,Maybe<&1,List<&2,U32>>>,Unit> <-
          wait_socket(~U32,~ReadReply(),~Unit,~tcp_receive,mode,left,socket,Unit{},ms)
        read_more(received,next => +bytes => read_exact(k,next,U32.sub(left,count_bytes(bytes)),ms,
          List.append(&2,U32,List.reverse(&2,U32,bytes),reversed),mode))
    case 0n _:
      IO.pure(Socket & TcpChunk,(socket,ReadFailed{1,"incomplete DNS TCP frame"}))

def tcp_reply(chunk: TcpChunk, request: Query) -> Result<&1,&1,U32 & String,Reply>:
  match chunk:
    case Chunk{+bytes}:
      Done{response_checked(bytes,request,Bytes.measure_limited(bytes,65535))}
    case ReadFailed{code,message}:
      Fail{(code,message)}

def finish_tcp(result: Socket & TcpChunk, request: Query)
    -> IO(Result<&1,&1,U32 & String,Reply>):
  (socket,chunk) = result
  do IO<Result<&1,&1,U32 & String,Reply>>:
    Socket.close(socket)
    return tcp_reply(chunk,request)

def read_tcp_body(socket: Socket, request: Query, +size: U32, ms: U32, valid: Bool, mode: WaitMode)
    -> IO(Result<&1,&1,U32 & String,Reply>):
  match valid:
    case True{}:
      do IO<Result<&1,&1,U32 & String,Reply>>:
        body : Socket & TcpChunk <- read_exact(U32.to_nat(size),socket,size,ms,[],mode)
        finish_tcp(body,request)
    case False{}:
      finish_tcp((socket,ReadFailed{1,"invalid DNS TCP frame length"}),request)

def read_tcp_frame(prefix: Socket & TcpChunk, request: Query, ms: U32, mode: WaitMode)
    -> IO(Result<&1,&1,U32 & String,Reply>):
  match prefix:
    case (socket,Chunk{Con{hi,Con{lo,Nil{}}}}):
      +size = be16(hi,lo)
      read_tcp_body(socket,request,size,ms,U32.is_ge(size,12),mode)
    case (socket,ReadFailed{code,message}):
      finish_tcp((socket,ReadFailed{code,message}),request)
    case (socket,_):
      finish_tcp((socket,ReadFailed{1,"invalid DNS TCP frame prefix"}),request)

def tcp_sent(sent: Socket & Poll<&1,&1,Result<&1,&1,(U32 & String) & List<&2,U32>,Unit>,List<&2,U32>>,
    request: Query, +ms: U32, +mode: WaitMode) -> IO(Result<&1,&1,U32 & String,Reply>):
  match sent:
    case (socket,Ready{Done{_}}):
      do IO<Result<&1,&1,U32 & String,Reply>>:
        prefix : Socket & TcpChunk <- read_exact(2n,socket,2,ms,[],mode)
        read_tcp_frame(prefix,request,ms,mode)
    case (socket,Ready{Fail{((code,message),_)}}):
      finish_tcp((socket,ReadFailed{code,message}),request)
    case (socket,Wait{_}):
      finish_tcp((socket,ReadFailed{1,"DNS TCP send timed out"}),request)

def tcp_query(conn: Result<&1,&1,U32 & String,Socket>, +request: Query, +ms: U32, +mode: WaitMode)
    -> IO(Result<&1,&1,U32 & String,Reply>):
  match conn request:
    case Done{socket} TxtQuery{_,_,+data}:
      +size = count_bytes(data)
      frame : List<&2,U32> = Con{U32.shrn(size,8n),Con{U32.and(size,255),data}}
      do IO<Result<&1,&1,U32 & String,Reply>>:
        sent : Socket & Poll<&1,&1,Result<&1,&1,(U32 & String) & List<&2,U32>,Unit>,List<&2,U32>> <-
          wait_socket(~Unit,~WriteReply(),~List<&2,U32>,~tcp_write,mode,Unit{},socket,frame,ms)
        tcp_sent(sent,request,ms,mode)
    case Done{socket} InvalidQuery{}:
      finish_tcp((socket,ReadFailed{1,"invalid Iroh discovery query"}),request)
    case Fail{error} _:
      IO.pure(Result<&1,&1,U32 & String,Reply>,Fail{error})

def retry_truncated(reply: Result<&1,&1,U32 & String,Reply>, request: Query,
    resolver: String, +port: U32, +ms: U32, mode: WaitMode, open_tcp: OpenTcp()) -> IO(Result<&1,&1,U32 & String,Reply>):
  match reply:
    case Done{Truncated{}}:
      do IO<Result<&1,&1,U32 & String,Reply>>:
        conn : Result<&1,&1,U32 & String,Socket> <- open_tcp(resolver,port,ms)
        tcp_query(conn,request,ms,mode)
    case _:
      IO.pure(Result<&1,&1,U32 & String,Reply>,reply)

def close_answer(outcome: Socket & Poll<&1,&1,Result<&1,&1,U32 & String,String & U32 & List<&2,U32>>,Unit>,
    +request: Query, +resolver: String, +port: U32, ms: U32, mode: WaitMode, open_tcp: OpenTcp()) -> IO(Result<&1,&1,U32 & String,Reply>):
  (socket,poll) = outcome
  do IO<Result<&1,&1,U32 & String,Reply>>:
    Socket.close(socket)
    retry_truncated(recv_result(poll,request,resolver,port),request,resolver,port,ms,mode,open_tcp)

def on_sent(outcome: SocketPoll(WriteReply(),List<&2,U32>), request: Query, resolver: String,
    port: U32, +ms: U32, +mode: WaitMode, open_tcp: OpenTcp()) -> IO(Result<&1,&1,U32 & String,Reply>):
  match outcome:
    case (socket,Ready{Done{_}}):
      do IO<Result<&1,&1,U32 & String,Reply>>:
        received : SocketPoll(UdpReply(),Unit) <-
          wait_socket(~U32,~UdpReply(),~Unit,~udp_receive,mode,4097,socket,Unit{},ms)
        close_answer(received,request,resolver,port,ms,mode,open_tcp)
    case (socket,Ready{Fail{(error,_)}}):
      do IO<Result<&1,&1,U32 & String,Reply>>:
        Socket.close(socket)
        return Fail{error}
    case (socket,Wait{_}):
      do IO<Result<&1,&1,U32 & String,Reply>>:
        Socket.close(socket)
        return Fail{(1,"DNS UDP send timed out")}

def on_bound(bound: Result<&1,&1,U32 & String,Socket>, request: Query, +resolver: String,
    +port: U32, +ms: U32, data: List<&2,U32>, +mode: WaitMode, open_tcp: OpenTcp())
    -> IO(Result<&1,&1,U32 & String,Reply>):
  match bound:
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Reply>,Fail{error})
    case Done{socket}:
      do IO<Result<&1,&1,U32 & String,Reply>>:
        sent : SocketPoll(WriteReply(),List<&2,U32>) <-
          send_query(mode,resolver,port,socket,data,ms)
        on_sent(sent,request,resolver,port,ms,mode,open_tcp)

def transact_with(+request: Query, resolver: String, port: U32, ms: U32, mode: WaitMode, open_tcp: OpenTcp())
    -> IO(Result<&1,&1,U32 & String,Reply>):
  match request:
    case TxtQuery{_,_,data}:
      do IO<Result<&1,&1,U32 & String,Reply>>:
        bound : Result<&1,&1,U32 & String,Socket> <- UDP.bind("0.0.0.0",0)
        on_bound(bound,request,resolver,port,ms,data,mode,open_tcp)
    case InvalidQuery{}:
      IO.pure(Result<&1,&1,U32 & String,Reply>,Fail{(1,"invalid Iroh discovery name")})

def transact(request: Query, resolver: String, port: U32, ms: U32) -> IO(Result<&1,&1,U32 & String,Reply>):
  transact_with(request,resolver,port,ms,TimedWait{},host => p => timeout => TCP.connect(host,p))

def lookup_using(random: Result<&1,&1,U32 & String,U32>, key: List<&2,U32>, origin: String,
    resolver: String, port: U32, ms: U32, mode: WaitMode, open_tcp: OpenTcp()) -> IO(Result<&1,&1,U32 & String,Reply>):
  match random:
    case Done{id}:
      transact_with(query(id,key,origin),resolver,port,ms,mode,open_tcp)
    case Fail{error}:
      IO.pure(Result<&1,&1,U32 & String,Reply>,Fail{error})

def lookup_with_id(random: Result<&1,&1,U32 & String,U32>, key: List<&2,U32>, origin: String,
    resolver: String, port: U32, ms: U32) -> IO(Result<&1,&1,U32 & String,Reply>):
  lookup_using(random,key,origin,resolver,port,ms,TimedWait{},host => p => timeout => TCP.connect(host,p))

# ms limits socket reads and the TCP send. TCP connection establishment uses
# Bend's socket effect and its operating-system connect timeout.
def lookup(key: List<&2,U32>, origin: String, resolver: String, port: U32, ms: U32)
    -> IO(Result<&1,&1,U32 & String,Reply>):
  do IO<Result<&1,&1,U32 & String,Reply>>:
    random : Result<&1,&1,U32 & String,U32> <- IO.random_u32()
    lookup_with_id(random,key,origin,resolver,port,ms)

# Signed Pkarr packets carry a DNS reply with an answer section and no query.
def parse_signed(+packet: List<&2,U32>, expected: List<&2,U32>, size: Bytes.Size) -> Reply:
  match packet size:
    case Con{_,Con{_,Con{128,Con{0,Con{0,Con{0,Con{ah,Con{al,Con{_,Con{_,Con{_,Con{_,records}}}}}}}}}}}} Bytes.Length{_}:
      answer_status(records,12,packet,expected,be16(ah,al),0)
    case _ _:
      InvalidReply{}

def signed_checked(+packet: List<&2,U32>, request: Query) -> Reply:
  match request:
    case TxtQuery{_,owner,_}:
      parse_signed(packet,owner,Bytes.measure_limited(packet,1000))
    case InvalidQuery{}:
      InvalidReply{}

def signed_records(key: List<&2,U32>, packet: List<&2,U32>) -> Reply:
  signed_checked(packet,query(0,key,""))

def txt_value(attr: Attribute) -> List<&2,U32>:
  match attr:
    case RelayUrl{value}:
      List.append(&2,U32,keyword("relay="),value)
    case Address{value}:
      List.append(&2,U32,keyword("addr="),value)
    case UserData{value}:
      List.append(&2,U32,keyword("user-data="),value)

def split_into_txt(+fuel: Nat, split: Bytes.Split, +size: U32, prefix: List<&2,U32>)
    -> List<&2,U32>:
  match fuel split:
    case 1n+k Bytes.Prefix{chunk,tail}:
      +left = U32.sub(size,255)
      split_into_txt(k,Bytes.split_peer(U32.to_nat(U32.min(255,left)),tail,[]),left,
        List.append(&2,U32,prefix,Con{255,chunk}))
    case 0n Bytes.Prefix{chunk,_}:
      List.append(&2,U32,prefix,Con{size,chunk})
    case _ _:
      []

def pack_txt(+text: List<&2,U32>, +size: U32) -> List<&2,U32>:
  split_into_txt(U32.to_nat(U32.div(U32.sub(size,1),255)),
    Bytes.split_peer(U32.to_nat(U32.min(size,255)),text,[]),size,[])

def high_byte(+value: U32, shift: Nat) -> U32:
  U32.and(U32.shrn(value,shift),255)

def build_rr(owner: List<&2,U32>, +data: List<&2,U32>, +ttl: U32, +size: U32) -> List<&2,U32>:
  List.append(&2,U32,owner,List.append(&2,U32,
    [0,16,0,1,high_byte(ttl,24n),high_byte(ttl,16n),high_byte(ttl,8n),high_byte(ttl,0n),
     high_byte(size,8n),high_byte(size,0n)],data))

def sized_txt(owner: List<&2,U32>, ttl: U32, +text: List<&2,U32>, size: Bytes.Size,
    valid: Bool) -> Maybe<&2,List<&2,U32>>:
  match size valid:
    case Bytes.Length{+n} True{}:
      +encoded = pack_txt(text,n)
      Some{build_rr(owner,encoded,ttl,count_bytes(encoded))}
    case _ _:
      None{}

def encode_txt(owner: List<&2,U32>, +ttl: U32, +text: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  sized_txt(owner,ttl,text,Bytes.measure_limited(text,1000),Bytes.utf8_scan(text,Bytes.Lead{}))

def concat_record(head: Maybe<&2,List<&2,U32>>, tail: Maybe<&2,List<&2,U32>>)
    -> Maybe<&2,List<&2,U32>>:
  match head tail:
    case Some{a} Some{b}:
      Some{List.append(&2,U32,a,b)}
    case _ _:
      None{}

def encode_records(items: List<&2,Attribute>, owner: List<&2,U32>, +ttl: U32)
    -> Maybe<&2,List<&2,U32>>:
  match items:
    case Nil{}:
      Some{[]}
    case Con{attr,tail}:
      concat_record(encode_txt(owner,ttl,txt_value(attr)),encode_records(tail,[192,12],ttl))

def cap_packet(bytes: List<&2,U32>, size: Bytes.Size) -> Maybe<&2,List<&2,U32>>:
  match size:
    case Bytes.Length{_}:
      Some{bytes}
    case _:
      None{}

def build_signed_packet(answer: Maybe<&2,List<&2,U32>>, +count: U32) -> Maybe<&2,List<&2,U32>>:
  match answer:
    case Some{records}:
      +packet = List.append(&2,U32,[0,0,128,0,0,0,high_byte(count,8n),high_byte(count,0n),0,0,0,0],records)
      cap_packet(packet,Bytes.measure_limited(packet,1000))
    case None{}:
      None{}

def encode_signed_records(request: Query, +items: List<&2,Attribute>, ttl: U32)
    -> Maybe<&2,List<&2,U32>>:
  match request:
    case TxtQuery{_,owner,_}:
      build_signed_packet(encode_records(items,owner,ttl),U32.from_nat(List.length(&2,Attribute,items)))
    case InvalidQuery{}:
      None{}

def signed_dns(key: List<&2,U32>, items: List<&2,Attribute>, ttl: U32)
    -> Maybe<&2,List<&2,U32>>:
  encode_signed_records(query(0,key,""),items,ttl)
