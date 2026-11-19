import Base
import ../src/bencode.bend as Ben
import ../src/discovery.bend as Bytes
import ../src/krpc.bend as Krpc
import ../src/pkarr.bend as Pkarr
import ../src/pkarr_dht.bend as Dht
import ../src/pkarr_dht_search.bend as Search
import ./pkarr.bend as Fixture

def report(label: String, ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print(String.append("PASS ",label))
    case False{}:
      IO.die(Unit,1,String.append("FAIL ",label))

def invalid(value: Maybe<&2,Ben.Value>) -> Bool:
  match value:
    case None{}:
      True{}
    case _:
      False{}

def decoded(value: Maybe<&2,Ben.Value>) -> Bool:
  match value:
    case Some{Ben.Dictionary{Con{Ben.ByteString{[97]},Con{
        Ben.Sequence{Con{Ben.Integer{[45,49]},Con{Ben.ByteString{[0,255]},Nil{}}}},Nil{}}}}}:
      True{}
    case _:
      False{}

def parser_fixture() -> Bool:
  decoded(Ben.decode([100,49,58,97,108,105,45,49,101,50,58,0,255,101,101])) &&
    invalid(Ben.decode(Bytes.keyword("d1:ai1e1:ai2ee"))) &&
    invalid(Ben.decode(Bytes.keyword("d1:ai01ee"))) &&
    invalid(Ben.decode(Bytes.keyword("d1:ai-0ee"))) &&
    invalid(Ben.decode(Bytes.keyword("d1:a02:xxe"))) &&
    invalid(Ben.decode(Bytes.keyword("d1:a2:xe"))) &&
    invalid(Ben.decode(Bytes.keyword("d1:ai1ee0:")))

def sequence_check(value: Maybe<&2,List<&2,U32>>, expected: List<&2,U32>) -> Bool:
  match value:
    case Some{bytes}:
      Bytes.bytes_eq(bytes,expected)
    case None{}:
      False{}

def no_sequence(value: Maybe<&2,List<&2,U32>>) -> Bool:
  match value:
    case None{}:
      True{}
    case _:
      False{}

def sequence_fixture() -> Bool:
  sequence_check(Krpc.timestamp(Some{Bytes.keyword("9223372036854775807")}),
    [127,255,255,255,255,255,255,255]) &&
    sequence_check(Krpc.timestamp(Some{Bytes.keyword("0")}),[0,0,0,0,0,0,0,0]) &&
    no_sequence(Krpc.timestamp(Some{Bytes.keyword("9223372036854775808")})) &&
    no_sequence(Krpc.timestamp(Some{Bytes.keyword("-1")}))

def tid_ok(reply: Krpc.Reply, unexpected: Krpc.Reply) -> Bool:
  match reply unexpected:
    case Krpc.KrpcResponse{_} Krpc.InvalidKrpcReply{}:
      True{}
    case _ _:
      False{}

def rpc_fixture(+bytes: List<&2,U32>) -> Bool:
  tid_ok(Krpc.reply(bytes,[0,255]),Krpc.reply(bytes,[255,0]))

def fixtures() -> IO(Unit):
  do IO<Unit>:
    report("bencode dictionaries, lists, binary values, and malformed input",parser_fixture())
    report("BEP 44 signed sequence limits",sequence_fixture())
    report("KRPC reply and transaction matching",
      rpc_fixture(Krpc.cat(Bytes.keyword("d1:rd2:id20:ABCDEFGHIJKLMNOPQRSTe1:t2:"),[0,255,49,58,121,49,58,114,101])))

def timestamp() -> List<&2,U32>:
  [0,0,0,0,0,0,0,42]

def node_id() -> List<&2,U32>:
  Bytes.keyword("bend-test-node-00001")

def valid(result: Maybe<&2,Pkarr.Verification>) -> Bool:
  match result:
    case Some{Pkarr.Verified{time,records}}:
      Bytes.bytes_eq(time,timestamp()) && Fixture.valid(Pkarr.Verified{List.replicate(U32,8n,255),records})
    case _:
      False{}

def absent(result: Maybe<&2,Pkarr.Verification>) -> Bool:
  match result:
    case None{}:
      True{}
    case _:
      False{}

def publish(peer: Dht.Peer) -> IO(Unit):
  do IO<Unit>:
    signed : List<&2,U32> <- IO.try(List<&2,U32>,
      Pkarr.sign(List.replicate(U32,32n,42),Fixture.key(),timestamp(),Fixture.records(),30))
    IO.try(Unit,Dht.publish_at(peer,node_id(),Fixture.key(),signed,2500))
    IO.print("PASS BEP 44 token exchange and Pkarr put")

def compare(result: Maybe<&2,Pkarr.Verification>, missing: Bool) -> IO(Unit):
  match missing:
    case True{}:
      report("BEP 44 missing value",absent(result))
    case False{}:
      report("BEP 44 Pkarr resolution and signature verification",valid(result))

def resolve(peer: Dht.Peer, missing: Bool) -> IO(Unit):
  do IO<Unit>:
    found : Maybe<&2,Pkarr.Verification> <- IO.try(Maybe<&2,Pkarr.Verification>,
      Dht.resolve_at(peer,node_id(),Fixture.key(),2500))
    compare(found,missing)

def signed_at(seq: U32) -> IO(List<&2,U32>):
  IO.try(List<&2,U32>,Pkarr.sign(List.replicate(U32,32n,42),Fixture.key(),
    [0,0,0,0,0,0,0,seq],Fixture.records(),30))

def search_publish(peer: Dht.Peer) -> IO(Unit):
  do IO<Unit>:
    signed : List<&2,U32> <- signed_at(42)
    count : U32 <- IO.try(U32,Search.publish([peer],node_id(),Fixture.key(),signed,400))
    report("DHT publication replicated to multiple peers",U32.is_ge(count,2))

def search_resolve(peer: Dht.Peer) -> IO(Unit):
  do IO<Unit>:
    proof : Maybe<&2,Pkarr.Verification> <- IO.try(Maybe<&2,Pkarr.Verification>,
      Search.resolve([peer],node_id(),Fixture.key(),400))
    report("DHT lookup follows referrals and selects the latest verified item",valid(proof))

def stale_result(result: Result<&1,&1,U32 & String,U32>) -> IO(Unit):
  match result:
    case Fail{(302,_)}:
      IO.print("PASS DHT stale publication rejected")
    case _:
      IO.die(Unit,1,"DHT accepted a stale publication")

def search_stale(peer: Dht.Peer) -> IO(Unit):
  do IO<Unit>:
    signed : List<&2,U32> <- signed_at(41)
    result : Result<&1,&1,U32 & String,U32> <- Search.publish([peer],node_id(),Fixture.key(),signed,400)
    stale_result(result)

def publish_old(peer: Dht.Peer) -> IO(Unit):
  do IO<Unit>:
    signed : List<&2,U32> <- signed_at(41)
    IO.try(Unit,Dht.publish_at(peer,node_id(),Fixture.key(),signed,400))

def against(mode: String, port: Maybe<&2,U32>) -> IO(Unit):
  match mode port:
    case "publish" Some{p}:
      publish(Dht.DhtPeer{"127.0.0.1",p})
    case "resolve" Some{p}:
      resolve(Dht.DhtPeer{"127.0.0.1",p},False{})
    case "missing" Some{p}:
      resolve(Dht.DhtPeer{"127.0.0.1",p},True{})
    case "publish-old" Some{p}:
      publish_old(Dht.DhtPeer{"127.0.0.1",p})
    case "search-publish" Some{p}:
      search_publish(Dht.DhtPeer{"127.0.0.1",p})
    case "search-resolve" Some{p}:
      search_resolve(Dht.DhtPeer{"127.0.0.1",p})
    case "search-stale" Some{p}:
      search_stale(Dht.DhtPeer{"127.0.0.1",p})
    case _ _:
      IO.die(Unit,2,"usage: pkarr-dht-check [mode port]")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Nil{}}:
      fixtures()
    case Con{_,Con{mode,Con{port,Nil{}}}}:
      against(mode,U32.read(port))
    case _:
      IO.die(Unit,2,"usage: pkarr-dht-check [mode port]")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
