import Base
import ../src/relay_server.bend as Relay
import ../src/relay_access.bend as Access
import ../src/relay_rate.bend as Rate
import ../src/relay_server_socket.bend as Net

def drive(fuel: Nat, server: Relay.Server) -> IO(Unit):
  match fuel:
    case 0n:
      Relay.stop(server)
    case 1n+left:
      do IO<Unit>:
        next : Relay.Server <- Relay.step(server)
        IO.sleep(2)
        drive(left,next)

def ready(bound: Relay.Server & U32) -> IO(Unit):
  (server,port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    drive(30000n,server)

def serve(cert: String, key: String, access: Access.Control, limits: Rate.Limits) -> IO(Unit):
  do IO<Unit>:
    bound : Relay.Server & U32 <- IO.try(Relay.Server & U32,
      Relay.bind_raw_configured("127.0.0.1",0,cert,key,access,limits))
    ready(bound)

def repeated(header: Maybe<&2,Net.RequestHeaderValues>, token: Maybe<&2,List<&2,U32>>) -> Bool:
  match header token:
    case Some{Net.HeaderValues{[[111,110,101],[],[116,119,111]]}} Some{[111,107,61,103,111]}:
      True{}
    case _ _:
      False{}

def checked(event: Access.AccessEvent, again: Access.Control) -> IO(Access.Control & Access.Decision):
  match event:
    case Access.Admission{+request}:
      IO.pure(Access.Control & Access.Decision,
        (again,Access.decision(repeated(Access.header(request,[88,45,70,105,120]),Access.token(request)))))
    case Access.Disconnected{_,_}:
      IO.pure(Access.Control & Access.Decision,(again,Access.Allow{}))

def policy(fuel: Nat) -> Access.Control:
  match fuel:
    case 1n+left:
      Access.ControlWith{event => checked(event,policy(left))}
    case 0n:
      Access.WithPolicy{Access.Allowlist{[]}}

def start(args: List<String>) -> IO(Unit):
  match args:
    case [_,cert,key]:
      serve(cert,key,Access.AllowAll{},Rate.Unlimited{})
    case [_,"rate"]:
      serve("","",Access.AllowAll{},Rate.ReceiveLimit{200,Some{124}})
    case [_,"headers"]:
      serve("","",policy(32n),Rate.Unlimited{})
    case _:
      serve("","",Access.AllowAll{},Rate.Unlimited{})

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    start(args)
