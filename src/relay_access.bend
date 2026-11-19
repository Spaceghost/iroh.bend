import Base
import ./relay.bend as Wire
import ./relay_server_socket.bend as Net

type Request is Data:
  Connecting{connection: U32, endpoint: List<&2,U32>, version: Wire.Version, details: Net.RequestDetails}

type AccessEvent is Data:
  Admission{request: Request}
  Disconnected{connection: U32, endpoint: List<&2,U32>}

type Decision is Data:
  Allow{}
  Deny{reason: Maybe<&2,List<&2,U32>>}

type Policy is Data:
  Allowlist{endpoints: List<&2,List<&2,U32>>}
  Denylist{endpoints: List<&2,List<&2,U32>>}
  SharedTokens{tokens: List<&2,List<&2,U32>>}

# A handler returns its next controller so it can own affine application state.
# The decision on Disconnected is ignored.
type Control is Type:
  AllowAll{}
  WithPolicy{policy: Policy}
  ControlWith{handle: AccessEvent -> IO(Control & Decision)}

def selected_token(bytes: List<&2,U32>, +fallback: Maybe<&2,List<&2,U32>>, found: Bool)
    -> Maybe<&2,List<&2,U32>>:
  match found:
    case True{}:
      Some{bytes}
    case False{}:
      fallback

def query_token(query: List<&2,List<&2,U32>>) -> Maybe<&2,List<&2,U32>>:
  match query:
    case Nil{}:
      None{}
    case Con{[116,111,107,101,110],_}:
      Some{[]}
    case Con{Con{116,Con{111,Con{107,Con{101,Con{110,Con{61,value}}}}}},_}:
      Some{value}
    case Con{_,rest}:
      query_token(rest)

def ascii(header: List<&2,U32>) -> Bool:
  match header:
    case Nil{}:
      True{}
    case Con{+head,rest}:
      U32.is_ge(head,32) && U32.is_le(head,126) && ascii(rest)

def lower_is(value: U32, lower: U32) -> Bool:
  U32.is_eq(U32.or(value,32),lower)

def bearer(header: List<&2,U32>) -> Maybe<&2,List<&2,U32>>:
  match header:
    case Con{b,Con{e,Con{a,Con{r,Con{e2,Con{r2,Con{32,value}}}}}}}:
      selected_token(value,None{},lower_is(b,98) && lower_is(e,101) && lower_is(a,97) &&
        lower_is(r,114) && lower_is(e2,101) && lower_is(r2,114))
    case _:
      None{}

def choose_token(found: Maybe<&2,List<&2,U32>>, fallback: Unit -> Maybe<&2,List<&2,U32>>,
    valid: Bool) -> Maybe<&2,List<&2,U32>>:
  match found valid:
    case _ False{}:
      None{}
    case Some{value} True{}:
      Some{value}
    case None{} True{}:
      fallback(Unit{})

def headers_token(headers: List<&2,List<&2,U32>>, query: List<&2,List<&2,U32>>)
    -> Maybe<&2,List<&2,U32>>:
  match headers:
    case Nil{}:
      query_token(query)
    case Con{+value,rest}:
      choose_token(bearer(value),_ => headers_token(rest,query),ascii(value))

# An Authorization Bearer header takes precedence over the first token query argument.
def token(request: Request) -> Maybe<&2,List<&2,U32>>:
  match request:
    case Connecting{_,_,_,Net.Details{_,Net.Fields{headers,query}}}:
      headers_token(headers,query)
    case _:
      None{}

def equal_bytes(a: List<&2,U32>, b: List<&2,U32>) -> Bool:
  match a b:
    case Nil{} Nil{}:
      True{}
    case Con{x,xs} Con{y,ys}:
      U32.is_eq(x,y) && equal_bytes(xs,ys)
    case _ _:
      False{}

def contains(values: List<&2,List<&2,U32>>, +key: List<&2,U32>) -> Bool:
  match values:
    case Nil{}:
      False{}
    case Con{value,rest}:
      equal_bytes(key,value) || contains(rest,key)

def has_token(presented: Maybe<&2,List<&2,U32>>, tokens: List<&2,List<&2,U32>>) -> Bool:
  match presented:
    case Some{Con{first,rest}}:
      contains(tokens,Con{first,rest})
    case _:
      False{}

def permitted(policy: Policy, +request: Request) -> Bool:
  match policy:
    case Allowlist{keys}:
      Connecting{_,key,_,_} = request
      contains(keys,key)
    case Denylist{keys}:
      Connecting{_,key,_,_} = request
      Bool.not(contains(keys,key))
    case SharedTokens{tokens}:
      has_token(token(request),tokens)

def decision(allowed: Bool) -> Decision:
  match allowed:
    case True{}:
      Allow{}
    case False{}:
      Deny{None{}}

def policy_event(policy: Policy, event: AccessEvent) -> Decision:
  match event:
    case Admission{request}:
      decision(permitted(policy,request))
    case Disconnected{_,_}:
      Allow{}

def process(control: Control, event: AccessEvent) -> IO(Control & Decision):
  match control:
    case AllowAll{}:
      IO.pure(Control & Decision,(AllowAll{},Allow{}))
    case WithPolicy{+rule}:
      IO.pure(Control & Decision,(WithPolicy{rule},policy_event(rule,event)))
    case ControlWith{handler}:
      handler(event)
