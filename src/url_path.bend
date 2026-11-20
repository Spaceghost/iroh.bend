import Base
import ./url_text.bend as T

def drive(s: String) -> Bool:
  match s:
    case SCon{c,SCon{':',SNil{}}}:
      T.letter(Char.to_u32(c))
    case SCon{c,SCon{'|',SNil{}}}:
      T.letter(Char.to_u32(c))
    case _:
      False{}

def drive_segment(s: String) -> String:
  match s:
    case SCon{c,SCon{'|',SNil{}}}:
      SCon{c,":"}
    case _:
      s

def slashes(s: String) -> String:
  match s:
    case SCon{'\\',t}:
      SCon{'/',slashes(t)}
    case SCon{c,t}:
      SCon{c,slashes(t)}
    case SNil{}:
      ""

def drop_slashes(s: String) -> String:
  match s:
    case SCon{'/',t}:
      drop_slashes(t)
    case _:
      s

def shorten(reversed: List<&2,String>, file: Bool) -> List<&2,String>:
  match reversed:
    case [+root]:
      Bool.pick(List<&2,String>,file && drive(root),[root],[])
    case Con{_,tail}:
      tail
    case Nil{}:
      []

def push(reversed: List<&2,String>, +part: String, file: Bool) -> List<&2,String>:
  match reversed part file:
    case Nil{} SNil{} True{}:
      []
    case Nil{} _ True{}:
      [Bool.pick(String,drive(part),drive_segment(part),T.encode(T.Path{},part))]
    case _ _ _:
      Con{T.encode(T.Path{},part),reversed}

def dot_kind(s: String) -> U32:
  match s:
    case ".":
      1
    case "%2e":
      1
    case "..":
      2
    case ".%2e":
      2
    case "%2e.":
      2
    case "%2e%2e":
      2
    case _:
      0

def segment(reversed: List<&2,String>, text: String, dots: U32, file: Bool) -> List<&2,String>:
  match dots:
    case 1:
      reversed
    case 2:
      shorten(reversed,file)
    case _:
      push(reversed,text,file)

def last_segment(reversed: List<&2,String>, part: String, dots: U32, +file: Bool) -> List<&2,String>:
  match dots:
    case 1:
      push(reversed,"",file)
    case 2:
      push(shorten(reversed,file),"",file)
    case _:
      push(reversed,part,file)

def segments(parts: List<&2,String>, reversed: List<&2,String>, +file: Bool) -> List<&2,String>:
  match parts:
    case Nil{}:
      List.reverse(&2,String,reversed)
    case [+part]:
      List.reverse(&2,String,last_segment(reversed,part,dot_kind(T.lower(part)),file))
    case Con{+part,rest}:
      segments(rest,segment(reversed,part,dot_kind(T.lower(part)),file),file)

def first_drive(parts: List<&2,String>) -> Bool:
  match parts:
    case Con{part,_}:
      drive(part)
    case Nil{}:
      False{}

type Path is Data:
  Path{text: String, drive_root: Bool}

def trailing(+s: String) -> String:
  Bool.pick(String,String.ends_with(s,"/"),s,s ++ "/")

def joined(+parts: List<&2,String>, file: Bool) -> Path:
  Path{trailing("/" ++ String.join(parts,"/")),file && first_drive(parts)}

def without_leading(s: String) -> String:
  match s:
    case SCon{'/',t}:
      t
    case _:
      s

def parse(s: String, +file: Bool) -> Path:
  joined(segments(String.split(without_leading(s),'/'),[],file),file)
