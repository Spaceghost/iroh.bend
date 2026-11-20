import Base
import ./url_text.bend as T
import ./url_path.bend as P
import ./url_ip.bend as Ip
import ./idna.bend as Idna
import ./relay.bend as Wire

type Scheme is Data:
  Special{port: U32}
  FileUrl{}
  Other{}

def kind(s: String) -> Scheme:
  match s:
    case "http":
      Special{80}
    case "ws":
      Special{80}
    case "https":
      Special{443}
    case "wss":
      Special{443}
    case "ftp":
      Special{21}
    case "file":
      FileUrl{}
    case _:
      Other{}

def special(scheme: Scheme) -> Bool:
  match scheme:
    case Other{}:
      False{}
    case _:
      True{}

def is_file(scheme: Scheme) -> Bool:
  match scheme:
    case FileUrl{}:
      True{}
    case _:
      False{}

def colon(n: U32) -> Bool:
  U32.is_eq(n,58)

def at_sign(n: U32) -> Bool:
  U32.is_eq(n,64)

def slash(n: U32) -> Bool:
  U32.is_eq(n,47)

def bracket(n: U32) -> Bool:
  U32.is_eq(n,93)

def hash(n: U32) -> Bool:
  U32.is_eq(n,35)

def question(n: U32) -> Bool:
  U32.is_eq(n,63)

def scheme_byte(+n: U32) -> Bool:
  T.letter(n) || T.digit(n) || U32.is_eq(n,43) || U32.is_eq(n,45) || U32.is_eq(n,46)

def scheme_ok(s: String) -> Bool:
  match s:
    case SNil{}:
      False{}
    case SCon{c,t}:
      T.letter(Char.to_u32(c)) && T.all(~(n => scheme_byte(n)),t)

def opaque_host_byte(n: U32) -> Bool:
  Bool.not(T.forbidden(n))

def valid_domain(s: String, valid: Bool) -> Maybe<&2,String>:
  match valid:
    case True{}:
      Maybe.bind(&2,String,String,Idna.to_ascii(s),d => Ip.domain_or_ipv4(d))
    case False{}:
      None{}

def domain(+s: String) -> Maybe<&2,String>:
  valid_domain(s,Wire.utf8_scan(T.octets(s),Wire.Lead{}))

def host(+s: String, scheme: Scheme) -> Maybe<&2,String>:
  match s scheme:
    case _ Other{}:
      Bool.pick(Maybe<&2,String>,T.all(~opaque_host_byte,s),Some{T.encode(T.Opaque{},s)},None{})
    case SNil{} FileUrl{}:
      Some{""}
    case SNil{} _:
      None{}
    case _ _:
      Maybe.bind(&2,String,String,T.unescape(s),d => domain(d))

def port_text(scheme: Scheme, +n: U32) -> String:
  match scheme:
    case Special{default}:
      Bool.pick(String,U32.is_eq(n,default),"",":" ++ U32.show(n))
    case _:
      ":" ++ U32.show(n)

def port_suffix(s: String, scheme: Scheme, empty_host: Bool) -> Maybe<&2,String>:
  match s scheme empty_host:
    case SNil{} _ _:
      Some{""}
    case _ FileUrl{} _:
      None{}
    case _ _ True{}:
      None{}
    case ":" _ _:
      Some{""}
    case SCon{':',digits} _ _:
      Maybe.map(&2,U32,String,n => port_text(scheme,n),Ip.digits(digits,10,65535,0))
    case _ _ _:
      None{}

def combine(a: Maybe<&2,String>, b: Maybe<&2,String>) -> Maybe<&2,String>:
  match a b:
    case Some{x} Some{y}:
      Some{x ++ y}
    case _ _:
      None{}

def hostname(parts: T.Split, +scheme: Scheme, users: Bool) -> Maybe<&2,String>:
  match parts users:
    case T.Split{SNil{},_} True{}:
      None{}
    case T.Split{+name,tail} _:
      combine(host(name,scheme),port_suffix(tail,scheme,String.is_empty(name)))

def ipv6_host(parts: T.Split, scheme: Scheme) -> Maybe<&2,String>:
  match parts:
    case T.Split{inside,SCon{']',after}}:
      combine(Ip.ipv6(inside),port_suffix(after,scheme,False{}))
    case _:
      None{}

def host_port(s: String, scheme: Scheme, users: Bool) -> Maybe<&2,String>:
  match s:
    case SCon{'[',t}:
      ipv6_host(T.split(~bracket,t),scheme)
    case _:
      hostname(T.split(~colon,s),scheme,users)

def credentials(parts: T.Split) -> String:
  match parts:
    case T.Split{SNil{},SNil{}}:
      ""
    case T.Split{SNil{},":"}:
      ""
    case T.Split{user,SCon{':',SCon{c,t}}}:
      T.encode(T.UserInfo{},user) ++ (":" ++ (T.encode(T.UserInfo{},SCon{c,t}) ++ "@"))
    case T.Split{user,_}:
      T.encode(T.UserInfo{},user) ++ "@"

def authority(parts: T.Split, scheme: Scheme) -> Maybe<&2,String>:
  match parts scheme:
    case T.Split{host,SNil{}} _:
      host_port(String.reverse(host),scheme,False{})
    case _ FileUrl{}:
      None{}
    case T.Split{host,SCon{'@',user}} _:
      auth = credentials(T.split(~colon,String.reverse(user)))
      Maybe.map(&2,String,String,h => auth ++ h,host_port(String.reverse(host),scheme,True{}))
    case _ _:
      None{}

def with_path(+auth: String, path: P.Path, +file: Bool) -> String:
  P.Path{s,drive} = path
  "//" ++ (Bool.pick(String,file && (drive || String.eq(auth,"localhost")),"",auth) ++ s)

def with_authority(parts: T.Split, +scheme: Scheme) -> Maybe<&2,String>:
  T.Split{+auth,path} = parts
  +file = is_file(scheme)
  Maybe.map(&2,String,String,h => with_path(h,P.parse(path,file),file),
    authority(T.split(~at_sign,String.reverse(auth)),scheme))

def file_authority(+parts: T.Split, is_drive: Bool) -> Maybe<&2,String>:
  match parts is_drive:
    case T.Split{drive,rest} True{}:
      Some{with_path("",P.parse(drive ++ rest,True{}),True{})}
    case _ False{}:
      with_authority(parts,FileUrl{})

def file_parts(+parts: T.Split) -> Maybe<&2,String>:
  T.Split{head,_} = parts
  file_authority(parts,P.drive(head))

def file(s: String) -> Maybe<&2,String>:
  match s:
    case SCon{'/',SCon{'/',t}}:
      file_parts(T.split(~slash,t))
    case _:
      Some{with_path("",P.parse(s,True{}),True{})}

def hostless(path: P.Path) -> String:
  P.Path{+s,_} = path
  Bool.pick(String,String.starts_with(s,"//"),"/." ++ s,s)

def body(s: String, +scheme: Scheme) -> Maybe<&2,String>:
  match s scheme:
    case SCon{'/',SCon{'/',t}} Other{}:
      with_authority(T.split(~slash,t),scheme)
    case SCon{'/',_} Other{}:
      Some{hostless(P.parse(s,False{}))}
    case _ Other{}:
      Some{T.encode(T.Opaque{},s)}
    case _ FileUrl{}:
      file(P.slashes(s))
    case _ Special{_}:
      with_authority(T.split(~slash,P.drop_slashes(P.slashes(s))),scheme)

def suffix(s: String, component: T.Component) -> String:
  match s:
    case SCon{c,t}:
      SCon{c,T.encode(component,t)}
    case SNil{}:
      ""

def with_query(parts: T.Split, +scheme: Scheme, name: String, fragment: String) -> Maybe<&2,String>:
  T.Split{path,query} = parts
  tail = suffix(query,T.Query{special(scheme)}) ++ suffix(fragment,T.Fragment{})
  Maybe.map(&2,String,String,s => name ++ (":" ++ (s ++ tail)),body(path,scheme))

def with_fragment(parts: T.Split, +name: String) -> Maybe<&2,String>:
  T.Split{head,fragment} = parts
  with_query(T.split(~question,head),kind(name),name,fragment)

def after_scheme(parts: T.Split) -> Maybe<&2,String>:
  match parts:
    case T.Split{+name,SCon{':',t}}:
      Maybe.bind(&2,String,String,Bool.pick(Maybe<&2,String>,scheme_ok(name),Some{T.lower(name)},None{}),
        scheme => with_fragment(T.split(~hash,t),scheme))
    case _:
      None{}

def checked(bytes: List<&2,U32>, valid: Bool) -> Maybe<&2,List<&2,U32>>:
  match valid:
    case True{}:
      Maybe.map(&2,String,List<&2,U32>,T.octets,after_scheme(T.split(~colon,T.clean(T.text(bytes)))))
    case False{}:
      None{}

def normalize(+bytes: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  checked(bytes,Wire.utf8_scan(bytes,Wire.Lead{}))
