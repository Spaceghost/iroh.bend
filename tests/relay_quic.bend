import Base
import ../src/direct.bend as Direct
import ../src/discovery.bend as Dns
import ../src/endpoint.bend as Endpoint
import ../src/pkarr.bend as Pkarr
import ../src/pkarr_http.bend as Http
import ../src/pkarr_publisher.bend as Publisher
import ../src/relay_quic.bend as Path
import ../src/quic_datagram.bend as Quic
import ./direct.bend as Fixture
import ./quic_streams.bend as Stream
import ./quic_datagram.bend as TransportFixture

def serve_path(listener: Direct.QuicListener, path: Path.Bridge & U32) -> IO(Unit):
  (bridge,_) = path
  do IO<Unit>:
    IO.print("relay QUIC listener ready")
    request : Direct.QuicStream & List<&2,U32> <- IO.try(Direct.QuicStream & List<&2,U32>,Direct.accept(listener,1024))
    Fixture.echo(request)
    IO.try(Unit,Path.stop(bridge))

def answer(bound: Direct.QuicListener & U32, url: String) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    path : Path.Bridge & U32 <- IO.try(Path.Bridge & U32,
      Path.start(url,List.replicate(U32,32n,42),Fixture.dialer_public(),port))
    serve_path(listener,path)

def listen(url: String) -> IO(Unit):
  do IO<Unit>:
    bound : Direct.QuicListener & U32 <- IO.try(Direct.QuicListener & U32,
      Direct.bind("127.0.0.1",0,List.replicate(U32,32n,42),Fixture.dialer_public(),Fixture.alpn()))
    answer(bound,url)

def exchange(path: Path.Bridge & U32) -> IO(Unit):
  (bridge,port) = path
  do IO<Unit>:
    response : Result<&1,&1,U32 & String,List<&2,U32>> <- Direct.exchange("127.0.0.1",port,List.replicate(U32,32n,73),
      Fixture.listener_public(),Fixture.alpn(),Fixture.payload(),1024)
    IO.try(Unit,Path.stop(bridge))
    echoed : List<&2,U32> <- IO.try(List<&2,U32>,IO.pure(Result<&1,&1,U32 & String,List<&2,U32>>,response))
    Fixture.assert_equal(Fixture.equal(echoed,Fixture.payload()))
    IO.print("PASS pinned QUIC stream exchanged over the Iroh relay")

def dial(url: String) -> IO(Unit):
  do IO<Unit>:
    path : Path.Bridge & U32 <- IO.try(Path.Bridge & U32,
      Path.start(url,List.replicate(U32,32n,73),Fixture.listener_public(),0))
    exchange(path)

def stream_exchange(opened: Direct.QuicConnection & Direct.QuicIoStream) -> IO(Unit):
  (conn,stream) = opened
  do IO<Unit>:
    written : Direct.QuicIoStream <- Stream.send(stream,Fixture.payload())
    outcome : Direct.QuicIoStream & List<&2,U32> <- Stream.read_all(32n,written,[])
    Stream.validate(outcome,Fixture.payload())
    Stream.drain(conn)

def verify_stream(conn: Direct.QuicConnection) -> IO(Unit):
  do IO<Unit>:
    opened : Direct.QuicConnection & Direct.QuicIoStream <-
      Stream.poll(Direct.QuicConnection,Direct.QuicIoStream,Stream.open_bidi,3000n,conn)
    stream_exchange(opened)

def verified_route(connected: Direct.QuicConnection & Maybe<&1,Path.Bridge>, relayed: Bool) -> IO(Unit):
  match connected relayed:
    case (conn,Some{bridge}) True{}:
      do IO<Unit>:
        verify_stream(conn)
        IO.try(Unit,Path.stop(bridge))
        IO.print("PASS QUIC used the selected relay path")
    case (conn,None{}) False{}:
      do IO<Unit>:
        verify_stream(conn)
        IO.print("PASS QUIC kept the direct path with no relay connection")
    case _ _:
      IO.die(Unit,1,"unexpected QUIC path selection")

def route(port: U32, url: String, direct_ms: U32)
    -> IO(Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Path.Bridge>>):
  Path.dial_with_fallback("127.0.0.1",port,direct_ms,url,6000,List.replicate(U32,32n,73),
    Fixture.listener_public(),Fixture.alpn())

def result_route(outcome: Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Path.Bridge>>, relayed: Bool)
    -> IO(Unit):
  match outcome:
    case Done{connected}:
      verified_route(connected,relayed)
    case Fail{(code,message)}:
      IO.die(Unit,code,message)

def check_deadline(waited: Bool) -> IO(Unit):
  match waited:
    case True{}:
      IO.pure(Unit,Unit{})
    case False{}:
      IO.die(Unit,1,"direct attempt ended before its handshake deadline")

def silent_path(bound: Socket & Result<&1,&1,U32 & String,U32>, url: String) -> IO(Unit):
  match bound:
    case (socket,Done{port}):
      do IO<Unit>:
        before : Nat <- IO.now()
        result : Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Path.Bridge>> <- route(port,url,250)
        after : Nat <- IO.now()
        Socket.close(socket)
        check_deadline(Nat.is_ge(Nat.sub(after,before),200n))
        result_route(result,True{})
        IO.print("PASS QUIC fallback followed the direct deadline")
    case (socket,Fail{(code,message)}):
      do IO<Unit>:
        Socket.close(socket)
        IO.die(Unit,code,message)

def expect_fallback(url: String) -> IO(Unit):
  do IO<Unit>:
    silent : Socket <- IO.try(Socket,UDP.bind("127.0.0.1",0))
    bound : Socket & Result<&1,&1,U32 & String,U32> <- Path.relay_loopback_port(silent)
    silent_path(bound,url)

def expect_direct(port: Maybe<&2,U32>) -> IO(Unit):
  match port:
    case Some{n}:
      do IO<Unit>:
        result : Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Path.Bridge>> <- route(n,"unused://relay",3000)
        result_route(result,False{})
    case None{}:
      IO.die(Unit,2,"expected the direct listener port")

def unreachable(result: Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Path.Bridge>>) -> IO(Unit):
  match result:
    case Fail{(_,"QUIC handshake timed out")}:
      IO.print("PASS failed relay handshake released the bridge")
    case _:
      IO.die(Unit,1,"expected the relay handshake to expire")

def silent_relay(port: Socket & Result<&1,&1,U32 & String,U32>, url: String) -> IO(Unit):
  match port:
    case (socket,Done{n}):
      do IO<Unit>:
        result : Result<&1,&1,U32 & String,Direct.QuicConnection & Maybe<&1,Path.Bridge>> <-
          Path.dial_with_fallback("127.0.0.1",n,120,url,200,List.replicate(U32,32n,73),
            Fixture.listener_public(),Fixture.alpn())
        Socket.close(socket)
        unreachable(result)
    case (socket,Fail{(code,message)}):
      do IO<Unit>:
        Socket.close(socket)
        IO.die(Unit,code,message)

def expect_unreachable(url: String) -> IO(Unit):
  do IO<Unit>:
    socket : Socket <- IO.try(Socket,UDP.bind("127.0.0.1",0))
    port : Socket & Result<&1,&1,U32 & String,U32> <- Path.relay_loopback_port(socket)
    silent_relay(port,url)

def peer_identity() -> Endpoint.Identity:
  Endpoint.PeerKeys{List.replicate(U32,32n,73),Fixture.listener_public(),Fixture.alpn()}

def endpoint_timeouts() -> Endpoint.Timeouts:
  Endpoint.HandshakeTimeouts{160,6000}

def route_fixture_result(correct: Bool) -> IO(Unit):
  match correct:
    case True{}:
      IO.print("PASS endpoint address parsing and upstream relative relay URLs")
    case False{}:
      IO.die(Unit,1,"endpoint routes differ from the address and relay fixtures")

def route_plan(plan: Endpoint.Routes) -> IO(Unit):
  match plan:
    case Endpoint.DialRoutes{[Endpoint.IpAddress{ip4,9000},Endpoint.IpAddress{ip6,7777}],[base,prefix,replaced]}:
      route_fixture_result(String.eq(ip4,"192.0.2.8") && String.eq(ip6,"2001:db8::42") &&
        String.eq(base,"wss://example.com/relay") && String.eq(prefix,"wss://example.com/prefix/relay") &&
        String.eq(replaced,"ws://[::1]:8000/a/relay"))
    case _:
      route_fixture_result(False{})

def plan_routes() -> IO(Unit):
  route_plan(Endpoint.routes([
    Dns.Address{Dns.keyword("192.0.2.8:9000")},
    Dns.Address{Dns.keyword("[2001:db8::42]:7777")},
    Dns.Address{Dns.keyword("127.0.0.1:65536")},
    Dns.Address{Dns.keyword("2001:db8::1:7755")},
    Dns.RelayUrl{Dns.keyword("https://example.com")},
    Dns.RelayUrl{Dns.keyword("https://example.com/prefix/")},
    Dns.RelayUrl{Dns.keyword("http://[::1]:8000/a/previous?discard=1#fragment")},
    Dns.RelayUrl{Dns.keyword("ftp://example.com/")},
    Dns.UserData{Dns.keyword("app metadata")}
  ]))

def signed_routes(url: String) -> IO(List<&2,U32>):
  do IO<List<&2,U32>>:
    stamp : List<&2,U32> <- IO.try(List<&2,U32>,Publisher.pkarr_timestamp())
    IO.try(List<&2,U32>,Pkarr.sign(List.replicate(U32,32n,42),Fixture.listener_public(),stamp,
      [Dns.Address{Dns.keyword("127.0.0.1:0")},Dns.RelayUrl{Dns.keyword(url)}],30))

def publish_route(pkarr_url: String, relay_url: String) -> IO(Unit):
  do IO<Unit>:
    signed : List<&2,U32> <- signed_routes(relay_url)
    IO.try(Unit,Http.publish(pkarr_url,Fixture.listener_public(),signed,1500))

def dial_pkarr(url: String) -> IO(Unit):
  do IO<Unit>:
    signed : List<&2,U32> <- signed_routes(url)
    outcome : Endpoint.Outcome() <- Endpoint.verify_and_dial(peer_identity(),signed,endpoint_timeouts())
    result_route(outcome,True{})

def dial_dns(port: Maybe<&2,U32>) -> IO(Unit):
  match port:
    case Some{n}:
      do IO<Unit>:
        outcome : Endpoint.Outcome() <- Endpoint.lookup_and_dial(peer_identity(),
          Endpoint.DnsResolver{"irohdns.example","127.0.0.1",n,1200},endpoint_timeouts())
        result_route(outcome,True{})
    case None{}:
      IO.die(Unit,2,"expected the DNS server port")

def endpoint_roundtrip(conn: Quic.DatagramConnection) -> IO(Quic.DatagramConnection & Unit):
  do IO<Quic.DatagramConnection & Unit>:
    checked : Quic.DatagramConnection <- TransportFixture.roundtrip(conn)
    return (checked,Unit{})

def disconnect_checked(pair: Endpoint.Connection() & Unit) -> IO(Unit):
  (conn,_) = pair
  do IO<Unit>:
    IO.try(Unit,Endpoint.disconnect(conn))
    IO.print("PASS endpoint exchanged streams and datagrams on the selected QUIC path")

def roundtrip_connected(conn: Endpoint.Connection()) -> IO(Unit):
  do IO<Unit>:
    checked : Endpoint.Connection() & Unit <- Endpoint.use_connection(Unit,conn,endpoint_roundtrip)
    disconnect_checked(checked)

def check_endpoint_path(connected: Endpoint.Connection(), relayed: Bool) -> IO(Unit):
  match connected relayed:
    case (conn,Some{bridge}) True{}:
      roundtrip_connected((conn,Some{bridge}))
    case (conn,None{}) False{}:
      roundtrip_connected((conn,None{}))
    case _ _:
      do IO<Unit>:
        _ : Result<&1,&1,U32 & String,Unit> <- Endpoint.disconnect(connected)
        IO.die(Unit,1,"endpoint selected the wrong QUIC path")

def check_endpoint(outcome: Endpoint.ConnectResult(), relayed: Bool) -> IO(Unit):
  match outcome:
    case Done{conn}:
      check_endpoint_path(conn,relayed)
    case Fail{(code,message)}:
      IO.die(Unit,code,message)

def endpoint_direct(host: String, port: Maybe<&2,U32>) -> IO(Unit):
  match port:
    case Some{n}:
      do IO<Unit>:
        outcome : Endpoint.ConnectResult() <- Endpoint.connect_routes(
          Endpoint.DialRoutes{[Endpoint.IpAddress{host,n}],[]},
          peer_identity(),Endpoint.HandshakeTimeouts{4000,6000})
        check_endpoint(outcome,False{})
    case None{}:
      IO.die(Unit,2,"expected a UDP port")

def endpoint_fallback(url: String, bound: Socket & Result<&1,&1,U32 & String,U32>) -> IO(Unit):
  match bound:
    case (socket,Done{port}):
      do IO<Unit>:
        outcome : Endpoint.ConnectResult() <- Endpoint.connect_routes(
          Endpoint.DialRoutes{[Endpoint.IpAddress{"127.0.0.1",port}],[url]},peer_identity(),endpoint_timeouts())
        Socket.close(socket)
        check_endpoint(outcome,True{})
    case (socket,Fail{(code,message)}):
      do IO<Unit>:
        Socket.close(socket)
        IO.die(Unit,code,message)

def dial_endpoint_fallback(url: String) -> IO(Unit):
  do IO<Unit>:
    socket : Socket <- IO.try(Socket,UDP.bind("127.0.0.1",0))
    port : Socket & Result<&1,&1,U32 & String,U32> <- Path.relay_loopback_port(socket)
    endpoint_fallback(url,port)

def dial_endpoint_pkarr(url: String) -> IO(Unit):
  do IO<Unit>:
    signed : List<&2,U32> <- signed_routes(url)
    outcome : Endpoint.ConnectResult() <- Endpoint.verify_and_connect(peer_identity(),signed,endpoint_timeouts())
    check_endpoint(outcome,True{})

def dial_endpoint_dns(port: Maybe<&2,U32>) -> IO(Unit):
  match port:
    case Some{n}:
      do IO<Unit>:
        outcome : Endpoint.ConnectResult() <- Endpoint.lookup_and_connect(peer_identity(),
          Endpoint.DnsResolver{"irohdns.example","127.0.0.1",n,1200},endpoint_timeouts())
        check_endpoint(outcome,True{})
    case None{}:
      IO.die(Unit,2,"expected the DNS server port")

def accept_endpoint_result(
    outcome: Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Endpoint.Connection()>>,
    retry: Quic.QuicDatagramListener -> IO(Quic.QuicDatagramListener & Endpoint.Connection()))
    -> IO(Quic.QuicDatagramListener & Endpoint.Connection()):
  match outcome:
    case (listener,Done{Some{conn}}):
      IO.pure(Quic.QuicDatagramListener & Endpoint.Connection(),(listener,conn))
    case (listener,Done{None{}}):
      do IO<Quic.QuicDatagramListener & Endpoint.Connection()>:
        IO.sleep(1)
        retry(listener)
    case (listener,Fail{(code,message)}):
      do IO<Quic.QuicDatagramListener & Endpoint.Connection()>:
        Endpoint.close_listener(listener)
        IO.die(Quic.QuicDatagramListener & Endpoint.Connection(),code,message)

def accept_endpoint(fuel: Nat, listener: Quic.QuicDatagramListener)
    -> IO(Quic.QuicDatagramListener & Endpoint.Connection()):
  match fuel:
    case 0n:
      do IO<Quic.QuicDatagramListener & Endpoint.Connection()>:
        Endpoint.close_listener(listener)
        IO.die(Quic.QuicDatagramListener & Endpoint.Connection(),1,"endpoint listener timed out")
    case 1n+left:
      do IO<Quic.QuicDatagramListener & Endpoint.Connection()>:
        outcome : Quic.QuicDatagramListener & Result<&1,&1,U32 & String,Maybe<&1,Endpoint.Connection()>> <-
          Endpoint.try_accept(listener)
        accept_endpoint_result(outcome,next => accept_endpoint(left,next))

def endpoint_server_exchange(connected: Endpoint.Connection(), label: U32) -> IO(Unit):
  match connected:
    case (conn,None{}):
      TransportFixture.server_exchange(conn,label)
    case _:
      do IO<Unit>:
        _ : Result<&1,&1,U32 & String,Unit> <- Endpoint.disconnect(connected)
        IO.die(Unit,1,"direct endpoint accepted an unexpected relay path")

def serve_endpoint_pair(second: Quic.QuicDatagramListener & Endpoint.Connection(), first: Endpoint.Connection()) -> IO(Unit):
  (listener,conn) = second
  do IO<Unit>:
    Endpoint.close_listener(listener)
    endpoint_server_exchange(first,41)
    endpoint_server_exchange(conn,42)
    IO.print("PASS endpoint listener preserved both shared QUIC connections")

def accept_second_endpoint(first: Quic.QuicDatagramListener & Endpoint.Connection()) -> IO(Unit):
  (listener,conn) = first
  do IO<Unit>:
    second : Quic.QuicDatagramListener & Endpoint.Connection() <- accept_endpoint(15000n,listener)
    serve_endpoint_pair(second,conn)

def serve_endpoint(bound: Quic.QuicDatagramListener & U32, prefix: String) -> IO(Unit):
  (listener,port) = bound
  do IO<Unit>:
    IO.print(String.append(prefix,U32.show(port)))
    first : Quic.QuicDatagramListener & Endpoint.Connection() <- accept_endpoint(15000n,listener)
    accept_second_endpoint(first)

def listen_endpoint(host: String, prefix: String) -> IO(Unit):
  do IO<Unit>:
    bound : Quic.QuicDatagramListener & U32 <- IO.try(Quic.QuicDatagramListener & U32,
      Endpoint.bind(Endpoint.IpAddress{host,0},
        Endpoint.PeerKeys{List.replicate(U32,32n,42),Fixture.dialer_public(),Fixture.alpn()}))
    serve_endpoint(bound,prefix)

def wait_bridge(bound: Path.Bridge & U32) -> IO(Unit):
  (bridge,_) = bound
  do IO<Unit>:
    IO.print("endpoint relay bridge ready")
    IO.sleep(25000)
    IO.try(Unit,Path.stop(bridge))

def bridge_endpoint(url: String, port: Maybe<&2,U32>) -> IO(Unit):
  match port:
    case Some{n}:
      do IO<Unit>:
        bound : Path.Bridge & U32 <- IO.try(Path.Bridge & U32,
          Path.start(url,List.replicate(U32,32n,42),Fixture.dialer_public(),n))
        wait_bridge(bound)
    case None{}:
      IO.die(Unit,2,"expected a UDP port")

def run(args: List<String>) -> IO(Unit):
  match args:
    case Con{_,Con{"listen",Con{url,Nil{}}}}:
      listen(url)
    case Con{_,Con{"dial",Con{url,Nil{}}}}:
      dial(url)
    case Con{_,Con{"dial-fallback",Con{url,Nil{}}}}:
      expect_fallback(url)
    case Con{_,Con{"listen-direct",Nil{}}}:
      Fixture.listen("127.0.0.1","",False{})
    case Con{_,Con{"dial-direct",Con{port,Nil{}}}}:
      expect_direct(U32.read(port))
    case Con{_,Con{"dial-unreachable",Con{url,Nil{}}}}:
      expect_unreachable(url)
    case Con{_,Con{"endpoint-plan",Nil{}}}:
      plan_routes()
    case Con{_,Con{"dial-pkarr",Con{url,Nil{}}}}:
      dial_pkarr(url)
    case Con{_,Con{"dial-dns",Con{port,Nil{}}}}:
      dial_dns(U32.read(port))
    case Con{_,Con{"publish-route",Con{pkarr_url,Con{relay_url,Nil{}}}}}:
      publish_route(pkarr_url,relay_url)
    case Con{_,Con{"dial-endpoint-direct",Con{host,Con{port,Nil{}}}}}:
      endpoint_direct(host,U32.read(port))
    case Con{_,Con{"dial-endpoint-fallback",Con{url,Nil{}}}}:
      dial_endpoint_fallback(url)
    case Con{_,Con{"dial-endpoint-pkarr",Con{url,Nil{}}}}:
      dial_endpoint_pkarr(url)
    case Con{_,Con{"dial-endpoint-dns",Con{port,Nil{}}}}:
      dial_endpoint_dns(U32.read(port))
    case Con{_,Con{"bridge-endpoint",Con{url,Con{port,Nil{}}}}}:
      bridge_endpoint(url,U32.read(port))
    case Con{_,Con{"listen-endpoint",Nil{}}}:
      listen_endpoint("127.0.0.1","127.0.0.1:")
    case Con{_,Con{"listen6-endpoint",Nil{}}}:
      listen_endpoint("::1","[::1]:")
    case _:
      IO.die(Unit,2,"usage: relay-quic-check listen|dial relay-url")

def main() -> IO(Unit):
  do IO<Unit>:
    args : List<String> <- IO.args()
    run(args)
