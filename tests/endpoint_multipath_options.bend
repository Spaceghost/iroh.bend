import Base
import ../src/endpoint.bend as Endpoint
import ../src/endpoint_multipath.bend as Multipath
import ../src/quic_multipath.bend as Quic
import ../src/quic_multipath_nat.bend as Nat
import ./endpoint_validation.bend as CheckOptions

def check_options(mode: String, id: Endpoint.Identity, port: Maybe<&2,U32>) -> IO(Unit):
  match mode port:
    case "address" Some{p}:
      do IO<Unit>:
        outcome : Quic.ConnectResult() <- Multipath.dial(CheckOptions.ip(p),id,100)
        CheckOptions.rejection(Quic.MultipathConnection,outcome)
    case "routes" Some{p}:
      do IO<Unit>:
        outcome : Multipath.RoutedResult() <- Multipath.connect_routed(CheckOptions.routes(p),id,CheckOptions.timeouts())
        CheckOptions.rejection(Multipath.RoutedConnection,outcome)
    case "dns" Some{p}:
      do IO<Unit>:
        outcome : Multipath.ConnectResult() <- Multipath.lookup_and_connect(id,CheckOptions.dns(p),CheckOptions.timeouts())
        CheckOptions.rejection(Multipath.Connection(),outcome)
    case "nat-direct" Some{p}:
      do IO<Unit>:
        outcome : Nat.ConnectResult() <- Multipath.connect_nat_direct(CheckOptions.ip(p),id,100,1)
        CheckOptions.rejection(Nat.Connection(),outcome)
    case "nat-relay" Some{p}:
      do IO<Unit>:
        outcome : Multipath.NatRelayResult() <- Multipath.connect_nat_relay(CheckOptions.url(p),id,CheckOptions.ip(0),100,1)
        CheckOptions.rejection(Multipath.NatRelayConnection(),outcome)
    case _ _:
      IO.die(Unit,2,"invalid multipath options test")

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_, "options", mode, choice, port]:
      do IO<Unit>:
        id : Endpoint.Identity <- CheckOptions.identity(choice)
        check_options(mode,id,U32.read(port))
    case _:
      IO.die(Unit,2,"expected options, test mode, identity choice and observer port")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
