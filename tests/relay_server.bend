import Base
import ../src/relay_server.bend as Relay

def drive(fuel: Nat, server: Relay.Server) -> IO(Unit):
  match fuel:
    case 1n+left:
      do IO<Unit>:
        next : Relay.Server <- Relay.step(server)
        IO.sleep(2)
        drive(left,next)
    case 0n:
      Relay.stop(server)

def run_server(bound: Relay.Server & U32) -> IO(Unit):
  (server,port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    drive(30000n,server)

def serve(cert: String, key: String) -> IO(Unit):
  do IO<Unit>:
    bound : Relay.Server & U32 <- IO.try(Relay.Server & U32,Relay.bind("127.0.0.1",0,cert,key))
    run_server(bound)

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Nil{}}:
      serve("","")
    case Con{_,Con{cert,Con{key,Nil{}}}}:
      serve(cert,key)
    case _:
      IO.die(Unit,2,"expected certificate and private key paths or no arguments")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
