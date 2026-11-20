import Base
import ../src/quic_multipath.bend as Qad

def pumped(result: Qad.QadServer & Result<&1,&1,U32 & String,Unit>,
    next: Qad.QadServer -> IO(Unit)) -> IO(Unit):
  match result:
    case (server,Done{_}):
      do IO<Unit>:
        IO.sleep(1)
        next(server)
    case (server,Fail{(code,message)}):
      do IO<Unit>:
        Qad.close_qad_server(server)
        IO.die(Unit,code,message)

def drive(fuel: Nat, server: Qad.QadServer) -> IO(Unit):
  match fuel:
    case 0n:
      Qad.close_qad_server(server)
    case 1n+left:
      do IO<Unit>:
        result : Qad.QadServer & Result<&1,&1,U32 & String,Unit> <- Qad.step_qad_server(server)
        pumped(result,next => drive(left,next))

def announce(bound: Qad.QadServer & U32) -> IO(Unit):
  (server,port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    drive(40000n,server)

def run(args: List<String>) -> IO(Unit):
  match args:
    case [_,host,certificate,key]:
      do IO<Unit>:
        bound : Qad.QadServer & U32 <- IO.try(Qad.QadServer & U32,Qad.bind_qad_server(host,0,certificate,key))
        announce(bound)
    case _:
      IO.die(Unit,2,"expected the local IP, PEM certificate chain and PEM private key")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
