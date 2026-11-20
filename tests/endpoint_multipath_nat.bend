import Base
import ../src/endpoint.bend as Endpoint
import ../src/endpoint_multipath.bend as Multipath
import ../src/quic_multipath.bend as Quic
import ../src/quic_multipath_nat.bend as Nat
import ../src/relay_quic.bend as Relay
import ./quic_multipath_bend.bend as Fixture

def finish_second(sent: Quic.MultipathConnection & U32, first: U32,
    relay: Maybe<&1,Relay.Bridge>) -> IO(Unit):
  (conn,second) = sent
  do IO<Unit>:
    replied_a : Quic.MultipathConnection <- Fixture.receive(4000n,conn,first,11,False{})
    replied_b : Quic.MultipathConnection <- Fixture.receive(4000n,replied_a,second,22,False{})
    IO.try(Unit,Multipath.disconnect((replied_b,relay)))
    IO.print("PASS endpoint exchanged streams over relay and punched UDP on one connection")

def send_on_direct(sent: Quic.MultipathConnection & U32, path: U32,
    relay: Maybe<&1,Relay.Bridge>) -> IO(Unit):
  (conn,first) = sent
  do IO<Unit>:
    stream : Quic.MultipathConnection & U32 <- Fixture.open(conn)
    second : Quic.MultipathConnection & U32 <- Fixture.send(stream,path,22)
    finish_second(second,first,relay)

def exchange_on(owner: Multipath.NatRelayConnection(), first: U32, path: U32) -> IO(Unit):
  ((conn,_),relay) = owner
  send_on_direct((conn,first),path,relay)

def fail_nat_relay(owner: Multipath.NatRelayConnection(), code: U32, message: String) -> IO(Unit):
  do IO<Unit>:
    _ : Result<&1,&1,U32 & String,Unit> <- Multipath.disconnect_nat_relay(owner)
    IO.die(Unit,code,message)

def relay_nat_progress(result: Multipath.NatRelayConnection() & Nat.NewPathResult(), first: U32,
    retry: Multipath.NatRelayConnection() -> IO(Unit)) -> IO(Unit):
  match result:
    case (owner,Done{Some{path}}):
      do IO<Unit>:
        IO.print("PASS endpoint opened the punched path from an Iroh relay handshake")
        exchange_on(owner,first,path)
    case (owner,Done{None{}}):
      do IO<Unit>:
        IO.sleep(1)
        retry(owner)
    case (owner,Fail{(code,message)}):
      fail_nat_relay(owner,code,message)

def wait_relay_nat(fuel: Nat, owner: Multipath.NatRelayConnection(), +first: U32) -> IO(Unit):
  match fuel:
    case 0n:
      fail_nat_relay(owner,1,"Iroh did not validate a punched path after relay bootstrap")
    case 1n+left:
      do IO<Unit>:
        progress : Multipath.NatRelayConnection() & Nat.NewPathResult() <- Multipath.step_nat_relay(owner)
        relay_nat_progress(progress,first,next => wait_relay_nat(left,next,first))

def punch_after_relay(sent: Quic.MultipathConnection & U32, state: Nat.Dialer, relay: Maybe<&1,Relay.Bridge>)
    -> IO(Unit):
  (conn,first) = sent
  wait_relay_nat(12000n,((conn,state),relay),first)

def exercise_relay(owner: Multipath.NatRelayConnection()) -> IO(Unit):
  ((conn,state),relay) = owner
  do IO<Unit>:
    datagrams : Quic.MultipathConnection <- Fixture.datagram_exchange(conn)
    stream : Quic.MultipathConnection & U32 <- Fixture.open(datagrams)
    first : Quic.MultipathConnection & U32 <- Fixture.send(stream,0,11)
    punch_after_relay(first,state,relay)

def relayed_nat(host: String, url: String) -> IO(Unit):
  do IO<Unit>:
    owner : Multipath.NatRelayConnection() <- IO.try(Multipath.NatRelayConnection(),
      Multipath.connect_nat_relay(url,Endpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.fixture_key(0),Fixture.text_alpn()},
        Endpoint.IpAddress{host,0},6000,64))
    exercise_relay(owner)


def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,host,url]:
      relayed_nat(host,url)
    case _:
      IO.die(Unit,2,"expected the local address and the relay URL")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
