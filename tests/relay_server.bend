import Base
import ../src/relay_server.bend as Relay
import ../src/relay_access.bend as Access
import ../src/relay_server_socket.bend as Net
import ../src/relay.bend as Wire
import ../src/relay_rate.bend as Rate

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

def serve(cert: String, key: String, access: Access.Control) -> IO(Unit):
  do IO<Unit>:
    bound : Relay.Server & U32 <- IO.try(Relay.Server & U32,Relay.bind_with_access("127.0.0.1",0,cert,key,access))
    run_server(bound)

def serve_limited(cert: String, key: String, burst: U32) -> IO(Unit):
  do IO<Unit>:
    bound : Relay.Server & U32 <- IO.try(Relay.Server & U32,
      Relay.bind_configured("127.0.0.1",0,cert,key,Access.AllowAll{},Rate.ReceiveLimit{200,Some{burst}}))
    run_server(bound)

def read_command_result(result: File & Result<&1,&1,U32 & String,String>) -> IO(String):
  (file,value) = result
  do IO<String>:
    File.close(file)
    return Result.default(&1,&1,U32 & String,String,value,"")

def read_command(opened: Result<&1,&1,U32 & String,File>) -> IO(String):
  match opened:
    case Done{file}:
      do IO<String>:
        value : File & Result<&1,&1,U32 & String,String> <- File.read(file,16)
        read_command_result(value)
    case Fail{_}:
      IO.pure(String,"")

def report_update(result: Relay.Server & Result<&1,&1,U32 & String,Unit>, command: String) -> IO(Relay.Server):
  match result:
    case (server,Done{_}):
      do IO<Relay.Server>:
        IO.print("rate applied " ++ command)
        return server
    case (server,Fail{_}):
      do IO<Relay.Server>:
        IO.print("rate rejected " ++ command)
        return server

def change_rate(server: Relay.Server, +command: String, limits: Rate.Limits) -> IO(Relay.Server):
  do IO<Relay.Server>:
    result : Relay.Server & Result<&1,&1,U32 & String,Unit> <- Relay.set_client_rate_limit(server,limits)
    report_update(result,command)

def update_rate(server: Relay.Server, command: String, unchanged: Bool) -> IO(Relay.Server):
  match command unchanged:
    case "unlimited" False{}:
      change_rate(server,"unlimited",Rate.Unlimited{})
    case "invalid" False{}:
      change_rate(server,"invalid",Rate.ReceiveLimit{9,None{}})
    case "replace" False{}:
      change_rate(server,"replace",Rate.ReceiveLimit{1000000,None{}})
    case _ _:
      IO.pure(Relay.Server,server)

def drive_commands(~update: Relay.Server -> String -> Bool -> IO(Relay.Server), fuel: Nat,
    +path: String, previous: String, server: Relay.Server) -> IO(Unit):
  match fuel:
    case 1n+left:
      do IO<Unit>:
        opened : Result<&1,&1,U32 & String,File> <- File.open(path,"r")
        IO.bind(String,Unit,read_command(opened),+command =>
          do IO<Unit>:
            updated : Relay.Server <- update(server,command,String.eq(command,previous))
            next : Relay.Server <- Relay.step(updated)
            IO.sleep(5)
            drive_commands(~update,left,path,command,next))
    case 0n:
      Relay.stop(server)

def run_commands(~update: Relay.Server -> String -> Bool -> IO(Relay.Server),
    bound: Relay.Server & U32, path: String) -> IO(Unit):
  (server,port) = bound
  do IO<Unit>:
    IO.print(U32.show(port))
    drive_commands(~update,10000n,path,"",server)

def serve_live(cert: String, key: String, path: String) -> IO(Unit):
  do IO<Unit>:
    bound : Relay.Server & U32 <- IO.try(Relay.Server & U32,
      Relay.bind_configured("127.0.0.1",0,cert,key,Access.AllowAll{},Rate.ReceiveLimit{10,Some{1}}))
    run_commands(~update_rate,bound,path)

def relay_path(path: List<&2,U32>) -> Bool:
  match path:
    case [47,114,101,108,97,121]:
      True{}
    case _:
      False{}

def decision(token: Maybe<&2,List<&2,U32>>, valid_path: Bool) -> Access.Decision:
  match token valid_path:
    case Some{[97,108,108,111,119]} True{}:
      Access.Allow{}
    case Some{_} _:
      Access.Deny{Some{[102,105,120,116,117,114,101,32,100,101,110,105,101,100,32,
        226,152,131,32,240,159,154,171]}}
    case _ _:
      Access.Deny{None{}}

def checked(next: Access.Control, id: U32, value: Access.Decision) -> IO(Access.Control & Access.Decision):
  match value:
    case Access.Allow{}:
      do IO<Access.Control & Access.Decision>:
        IO.print("admitted " ++ U32.show(id))
        return (next,Access.Allow{})
    case Access.Deny{reason}:
      do IO<Access.Control & Access.Decision>:
        IO.print("denied " ++ U32.show(id))
        return (next,Access.Deny{reason})

def check_event(event: Access.AccessEvent, next: Access.Control) -> IO(Access.Control & Access.Decision):
  match event:
    case Access.Admission{Access.Connecting{id,key,version,Net.Details{+path,fields}}}:
      checked(next,id,decision(Access.token(Access.Connecting{0,key,version,Net.Details{path,fields}}),relay_path(path)))
    case Access.Admission{_}:
      IO.die(Access.Control & Access.Decision,1,"missing authenticated request metadata")
    case Access.Disconnected{id,_}:
      do IO<Access.Control & Access.Decision>:
        IO.print("closed " ++ U32.show(id))
        return (next,Access.Allow{})

def access_fixture(fuel: Nat) -> Access.Control:
  match fuel:
    case 1n+left:
      Access.ControlWith{entry => check_event(entry,access_fixture(left))}
    case 0n:
      Access.ControlWith{_ => IO.die(Access.Control & Access.Decision,1,"fixture event limit exceeded")}

def disconnect_key() -> List<&2,U32>:
  [25,127,107,35,225,108,133,50,198,171,200,56,250,205,94,167,
   137,190,12,118,178,146,3,52,3,155,250,139,61,54,141,97]

def other_key() -> List<&2,U32>:
  [119,44,138,68,43,125,176,110,22,108,251,193,204,188,188,222,
   111,62,186,118,164,233,142,243,255,197,25,80,34,55,214,239]

def report_disconnect(result: Relay.Server & Bool, command: String) -> IO(Relay.Server):
  match result:
    case (server,True{}):
      do IO<Relay.Server>:
        IO.print("disconnect applied " ++ command)
        return server
    case (server,False{}):
      do IO<Relay.Server>:
        IO.print("disconnect missing " ++ command)
        return server

def request_disconnect(server: Relay.Server, key: List<&2,U32>, id: Maybe<&2,U32>, command: String)
    -> IO(Relay.Server):
  do IO<Relay.Server>:
    result : Relay.Server & Bool <- Relay.disconnect(server,key,id)
    report_disconnect(result,command)

def request_one(server: Relay.Server, key: List<&2,U32>, id: Maybe<&2,U32>, command: String) -> IO(Relay.Server):
  match id:
    case Some{n}:
      request_disconnect(server,key,Some{n},command)
    case None{}:
      IO.pure(Relay.Server,server)

def disconnect_command(server: Relay.Server, words: List<&2,String>) -> IO(Relay.Server):
  match words:
    case ["one",+id]:
      request_one(server,disconnect_key(),U32.read(id),"one " ++ id)
    case ["wrong",+id]:
      request_one(server,other_key(),U32.read(id),"wrong " ++ id)
    case ["all"]:
      request_disconnect(server,disconnect_key(),None{},"all")
    case ["other"]:
      request_disconnect(server,other_key(),None{},"other")
    case _:
      IO.pure(Relay.Server,server)

def update_connections(server: Relay.Server, command: String, unchanged: Bool) -> IO(Relay.Server):
  match unchanged:
    case True{}:
      IO.pure(Relay.Server,server)
    case False{}:
      disconnect_command(server,String.split(command,Char.from_u32(32)))

def serve_disconnect(cert: String, key: String, path: String) -> IO(Unit):
  do IO<Unit>:
    bound : Relay.Server & U32 <- IO.try(Relay.Server & U32,
      Relay.bind_with_access("127.0.0.1",0,cert,key,access_fixture(24n)))
    run_commands(~update_connections,bound,path)

def duplicate_standard(values: Maybe<&2,Net.RequestHeaderValues>) -> Bool:
  match values:
    case Some{Net.HeaderValues{[[111,110,101],[116,119,111]]}}:
      True{}
    case _:
      False{}

def header_decision(custom: Maybe<&2,Net.RequestHeaderValues>, standard: Bool) -> Access.Decision:
  match custom standard:
    case Some{Net.HeaderValues{[[118,97,108,117,101]]}} True{}:
      Access.Allow{}
    case Some{Net.HeaderValues{Con{_,Con{_,_}}}} _:
      Access.Deny{Some{[97,109,98,105,103,117,111,117,115,32,104,101,97,100,101,114]}}
    case _ _:
      Access.Deny{None{}}

def check_headers(event: Access.AccessEvent, next: Access.Control) -> IO(Access.Control & Access.Decision):
  match event:
    case Access.Admission{+request}:
      # Mixed case in the lookup asks for the same HTTP field.
      custom = Access.header(request,[88,45,102,105,120])
      standard = Access.header(request,[97,99,99,101,112,116,45,108,97,110,103,117,97,103,101])
      IO.pure(Access.Control & Access.Decision,(next,header_decision(custom,duplicate_standard(standard))))
    case Access.Disconnected{_,_}:
      IO.pure(Access.Control & Access.Decision,(next,Access.Allow{}))

def header_fixture(fuel: Nat) -> Access.Control:
  match fuel:
    case 1n+left:
      Access.ControlWith{entry => check_headers(entry,header_fixture(left))}
    case 0n:
      Access.ControlWith{_ => IO.die(Access.Control & Access.Decision,1,"fixture event limit exceeded")}

def policy_result(ok: Bool) -> IO(Unit):
  match ok:
    case True{}:
      IO.print("PASS endpoint access allowlist and denylist")
    case False{}:
      IO.die(Unit,1,"incorrect relay endpoint policy")

def policy_test() -> IO(Unit):
  +listed = List.replicate(U32,32n,1)
  +allowed = {Access.Connecting{1,listed,Wire.V1{},Net.MissingDetails{}} : Access.Request}
  +other = {Access.Connecting{2,List.replicate(U32,32n,2),Wire.V2{},Net.MissingDetails{}} : Access.Request}
  policy_result(Access.permitted(Access.Allowlist{[listed]},allowed) &&
    Bool.not(Access.permitted(Access.Allowlist{[listed]},other)) &&
    Bool.not(Access.permitted(Access.Denylist{[listed]},allowed)) &&
    Access.permitted(Access.Denylist{[listed]},other))

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Nil{}}:
      serve("","",Access.AllowAll{})
    case Con{_,Con{"access",Nil{}}}:
      serve("","",access_fixture(20n))
    case Con{_,Con{"shared-token",Nil{}}}:
      serve("","",Access.WithPolicy{Access.SharedTokens{[[97,108,108,111,119]]}})
    case Con{_,Con{"headers",Nil{}}}:
      serve("","",header_fixture(8n))
    case Con{_,Con{"headers",Con{cert,Con{key,Nil{}}}}}:
      serve(cert,key,header_fixture(8n))
    case Con{_,Con{"rate",Nil{}}}:
      serve_limited("","",20)
    case Con{_,Con{"rate",Con{cert,Con{key,Nil{}}}}}:
      serve_limited(cert,key,20)
    case Con{_,Con{"fragment-rate",Nil{}}}:
      serve_limited("","",124)
    case Con{_,Con{"fragment-rate",Con{cert,Con{key,Nil{}}}}}:
      serve_limited(cert,key,124)
    case Con{_,Con{"live-rate",Con{path,Nil{}}}}:
      serve_live("","",path)
    case Con{_,Con{"live-rate",Con{path,Con{cert,Con{key,Nil{}}}}}}:
      serve_live(cert,key,path)
    case Con{_,Con{"disconnect",Con{path,Nil{}}}}:
      serve_disconnect("","",path)
    case Con{_,Con{"disconnect",Con{path,Con{cert,Con{key,Nil{}}}}}}:
      serve_disconnect(cert,key,path)
    case Con{_,Con{"policy-test",Nil{}}}:
      policy_test()
    case Con{_,Con{"access",Con{cert,Con{key,Nil{}}}}}:
      serve(cert,key,access_fixture(20n))
    case Con{_,Con{cert,Con{key,Nil{}}}}:
      serve(cert,key,Access.AllowAll{})
    case _:
      IO.die(Unit,2,"expected certificate and private key paths or no arguments")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
