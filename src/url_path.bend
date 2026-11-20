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

# url 2.5.8 retains the slash after a drive segment during double-dot
# shortening, including in hierarchical URLs with schemes other than file.
def drive_prefix(s: String) -> Bool:
  match s:
    case SCon{c,SCon{+d,SCon{'\\',_}}}:
      T.letter(Char.to_u32(c)) && (Char.is_eq(d,':') || Char.is_eq(d,'|'))
    case _:
      drive(s)

def shorten(+reversed: List<&2,String>) -> List<&2,String>:
  match reversed:
    case Con{head,tail}:
      Bool.pick(List<&2,String>,drive_prefix(head),reversed,tail)
    case Nil{}:
      []

def push(reversed: List<&2,String>, +part: String, file: Bool) -> List<&2,String>:
  match reversed part file:
    case Nil{} SNil{} True{}:
      []
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
      shorten(reversed)
    case _:
      push(reversed,text,file)

def last_segment(reversed: List<&2,String>, part: String, dots: U32, +file: Bool) -> List<&2,String>:
  match dots:
    case 1:
      push(reversed,"",file)
    case 2:
      push(shorten(reversed),"",file)
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

def normalize_root(parts: List<&2,String>, change: Bool) -> List<&2,String>:
  match parts change:
    case Con{head,tail} True{}:
      Con{drive_segment(head),tail}
    case _ _:
      parts

def joined(+parts: List<&2,String>, file: Bool, force_drive: Bool) -> Path:
  +drive = file && first_drive(parts)
  +raw = "/" ++ String.join(parts,"/")
  # Iroh sets the path a second time when appending a slash. That setter
  # normalizes a leading file drive even for a URL with an empty authority.
  change = drive && (force_drive || Bool.not(String.ends_with(raw,"/")))
  Path{trailing("/" ++ String.join(normalize_root(parts,change),"/")),drive}

def without_leading(s: String) -> String:
  match s:
    case SCon{'/',t}:
      t
    case _:
      s

def parse_mode(s: String, +file: Bool, force_drive: Bool) -> Path:
  joined(segments(String.split(without_leading(s),'/'),[],file),file,force_drive)

def parse(s: String, file: Bool) -> Path:
  parse_mode(s,file,True{})
