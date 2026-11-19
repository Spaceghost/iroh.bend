import Base
import ../src/discovery.bend as Dns

# The endpoint and answers from Iroh 1.5.0's test_from_txt_lookup.
def key() -> List<&2,U32>:
  [25,146,213,60,2,205,192,69,102,229,192,237,177,206,131,48,
   92,213,80,41,121,83,160,71,164,69,234,50,100,181,75,24]

def published_key() -> List<&2,U32>:
  [25,127,107,35,225,108,133,50,198,171,200,56,250,205,94,167,
   137,190,12,118,178,146,3,52,3,155,250,139,61,54,141,97]

def origin() -> String:
  "dns.iroh.link."

def name_matches(found: Maybe<&2,String>) -> Bool:
  match found:
    case Some{host}:
      String.eq(host,"_iroh.dgjpkxyn3zyrk3zfads5duwdgbqpkwbjxfj4yt7rezidr3fijccy.dns.iroh.link.")
    case None{}:
      False{}

def attr_bits(value: Dns.Attribute) -> U32:
  match value:
    case Dns.Address{+bytes}:
      U32.add(Bool.to_u32(Dns.bytes_eq(bytes,Dns.keyword("192.168.96.145:60165"))),
        U32.mul(2,Bool.to_u32(Dns.bytes_eq(bytes,Dns.keyword("213.208.157.87:60165")))))
    case Dns.RelayUrl{bytes}:
      U32.mul(4,Bool.to_u32(Dns.bytes_eq(bytes,Dns.keyword("https://euw1-1.relay.iroh.network./"))))
    case _:
      0

def attrs(reply: Dns.Reply) -> Bool:
  match reply:
    case Dns.Found{Con{a,Con{b,Con{c,Nil{}}}}}:
      U32.is_eq(U32.or(attr_bits(a),U32.or(attr_bits(b),attr_bits(c))),7)
    case _:
      False{}

def record(+owner: List<&2,U32>, +data: List<&2,U32>) -> List<&2,U32>:
  length = U32.from_nat(List.length(&2,U32,data))
  List.append(&2,U32,owner,List.append(&2,U32,[0,16,0,1,0,0,0,30,0,length],data))

def chunk(+text: List<&2,U32>) -> List<&2,U32>:
  Con{U32.from_nat(List.length(&2,U32,text)),text}

def answer(reply: List<&2,U32>, owner: List<&2,U32>, records: List<&2,U32>) -> List<&2,U32>:
  List.append(&2,U32,reply,List.append(&2,U32,owner,List.append(&2,U32,[0,16,0,1],records)))

def invalid(reply: Dns.Reply) -> Bool:
  match reply:
    case Dns.InvalidReply{}:
      True{}
    case _:
      False{}

def truncated(reply: Dns.Reply) -> Bool:
  match reply:
    case Dns.Truncated{}:
      True{}
    case _:
      False{}

def nx(reply: Dns.Reply) -> Bool:
  match reply:
    case Dns.DnsError{3}:
      True{}
    case _:
      False{}

def cases(+request: Dns.Query, +owner: List<&2,U32>) -> Bool:
  +header = {[18,52,129,128,0,1,0,3,0,0,0,0] : List<&2,U32>}
  +r1 = record([192,12],chunk(Dns.keyword("addr=192.168.96.145:60165")))
  +at = U32.add(16,U32.from_nat(List.length(&2,U32,owner)))
  +r2 = record([192,at],chunk(Dns.keyword("addr=213.208.157.87:60165")))
  +r3 = record([192,12],List.append(&2,U32,chunk(Dns.keyword("relay=https://euw1-1.")),
    chunk(Dns.keyword("relay.iroh.network./"))))
  +records = List.append(&2,U32,r1,List.append(&2,U32,r2,r3))
  attrs(Dns.response(request,answer(header,owner,records))) &&
    invalid(Dns.response(request,answer([18,53,129,128,0,1,0,3,0,0,0,0],owner,records))) &&
    invalid(Dns.response(request,answer(header,[1,120,0],records))) &&
    invalid(Dns.response(request,answer(header,owner,List.append(&2,U32,record([192,at],[1,65]),records)))) &&
    invalid(Dns.response(request,answer(header,owner,r1))) &&
    truncated(Dns.response(request,answer([18,52,131,128,0,1,0,0,0,0,0,0],owner,[]))) &&
    nx(Dns.response(request,answer([18,52,129,131,0,1,0,0,0,0,0,0],owner,[])))

def unit(+request: Dns.Query) -> Bool:
  match request:
    case Dns.TxtQuery{4660,owner,_}:
      cases(request,owner)
    case _:
      False{}

def report(message: String, success: Bool) -> IO(Unit):
  match success:
    case True{}:
      IO.print(String.append("PASS ",message))
    case False{}:
      IO.die(Unit,1,String.append("FAIL ",message))

def long_txt_value(response: Dns.Reply) -> Bool:
  match response:
    case Dns.Found{Con{Dns.UserData{bytes},Nil{}}}:
      Dns.bytes_eq(bytes,List.replicate(U32,257n,97))
    case _:
      False{}

def long_txt_record(packet: Maybe<&2,List<&2,U32>>) -> Bool:
  match packet:
    case Some{bytes}:
      long_txt_value(Dns.signed_records(key(),bytes))
    case _:
      False{}

def fixtures() -> IO(Unit):
  do IO<Unit>:
    report("upstream endpoint discovery z32 name",name_matches(Dns.name(key(),origin())))
    report("upstream endpoint TXT fixture, compression, and reply validation",unit(Dns.query(4660,key(),origin())))
    report("signed DNS TXT splits and rejoins long UTF-8 records",
      long_txt_record(Dns.signed_dns(key(),[Dns.UserData{List.replicate(U32,257n,97)}],30)))

def live(port: Maybe<&2,U32>, endpoint: List<&2,U32>) -> IO(Unit):
  match port:
    case Some{p}:
      do IO<Unit>:
        result : Dns.Reply <- IO.try(Dns.Reply,Dns.lookup(endpoint,origin(),"127.0.0.1",p,2500))
        report("Iroh endpoint TXT lookup over UDP",attrs(result))
    case None{}:
      IO.die(Unit,2,"invalid resolver port")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Nil{}}:
      fixtures()
    case Con{_,Con{port,Nil{}}}:
      live(U32.read(port),key())
    case Con{_,Con{port,Con{_,Nil{}}}}:
      live(U32.read(port),published_key())
    case _:
      IO.die(Unit,2,"usage: discovery-check [resolver-port [published]]")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
