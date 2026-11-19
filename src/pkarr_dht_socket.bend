import Base

def dht_bind() -> IO(Result<&1,&1,U32 & String,Socket>):
  import "./pkarr_dht_socket.c"

def dht_ipv6_bytes(host: String) -> IO(List<&2,U32>):
  import "./pkarr_dht_socket.c"

def dht_send(socket: Socket, host: String, port: U32, packet: List<&2,U32>, ms: U32)
    -> IO(Socket & Result<&1,&1,U32 & String,Unit>):
  import "./pkarr_dht_socket.c"

def dht_receive(socket: Socket, host: String, port: U32, ms: U32)
    -> IO(Socket & Result<&1,&1,U32 & String,List<&2,U32>>):
  import "./pkarr_dht_socket.c"
