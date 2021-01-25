import endians
import nimcrypto/[scrypt, hmac]

type
  MasterKey* = array[64, byte]
  SiteKey* = array[32, byte]

  Identicon* = object
    leftArm*, body*, rightArm*, accessory*: string
    color*: uint8

const
  scopePrefix* = "com.lyndir.masterpassword"
  scopePrefixId* = scopePrefix & ".login"
  scopePrefixRec* = scopePrefix & ".answer"

  templateMaximum* = ["anoxxxxxxxxxxxxxxxxx", "axxxxxxxxxxxxxxxxxno"]
  templateLong* = [
    "CvcvnoCvcvCvcv", "CvcvCvcvnoCvcv", "CvcvCvcvCvcvno", "CvccnoCvcvCvcv",
    "CvccCvcvnoCvcv", "CvccCvcvCvcvno", "CvcvnoCvccCvcv", "CvcvCvccnoCvcv",
    "CvcvCvccCvcvno", "CvcvnoCvcvCvcc", "CvcvCvcvnoCvcc", "CvcvCvcvCvccno",
    "CvccnoCvccCvcv", "CvccCvccnoCvcv", "CvccCvccCvcvno", "CvcvnoCvccCvcc",
    "CvcvCvccnoCvcc", "CvcvCvccCvccno", "CvccnoCvcvCvcc", "CvccCvcvnoCvcc",
    "CvccCvcvCvccno"]
  templateMedium* = ["CvcnoCvc", "CvcCvcno"]
  templateShort* = ["Cvcn"]
  templateBasic* = ["aaanaaan", "aannaaan", "aaannaaa"]
  templatePin* = ["nnnn"]

  identiconLeftArms = ["╔", "╚", "╰", "═"]
  identiconRightArms = ["╗", "╝", "╯", "═"]
  identiconBodies = ["█", "░", "▒", "▓", "☺", "☻"]
  identiconAccessories = [
    "◈", "◎", "◐", "◑", "◒", "◓", "☀", "☁", "☂", "☃", "", "★", "☆", "☎", "☏",
    "⎈", "⌂", "☘", "☢", "☣", "☕", "⌚", "⌛", "⏰", "⚡", "⛄", "⛅", "☔",
    "♔", "♕", "♖", "♗", "♘", "♙", "♚", "♛", "♜", "♝", "♞", "♟", "♨", "♩", "♪",
    "♫", "⚐", "⚑", "⚔", "⚖", "⚙", "⚠", "⌘", "⏎", "✄", "✆", "✈", "✉", "✌"]

func `$`*(i: Identicon): string =
  i.leftArm & i.body & i.rightArm & i.accessory

func genMasterKey(pass, salt: openArray[char]): MasterKey =
  const (xl, bl) = scryptCalc(32768, 8, 2)
  var
    xyv = newSeq[uint32](xl)
    b: array[bl, byte]
  if scrypt(pass, salt, 32768, 8, 2, xyv, b, result) != sizeof MasterKey:
    raise newException(CatchableError, "scrypt failed")

func bigEndStr(i: SomeNumber): string =
  result = newString 4
  bigEndian32 addr result[0], unsafeAddr i

func add(s: var string, a: openArray[char]) =
  let start = s.len
  s.setLen s.len + a.len
  copyMem addr s[start], unsafeAddr a[0], a.len

func getMasterKey*(pass, name: openArray[char], scope = scopePrefix): MasterKey =
  var salt = scope & name.len.bigEndStr
  salt.add name
  genMasterKey(pass, salt)

func getSiteKey*(pass: openArray[byte], site: openArray[char], n = 1, scope = scopePrefix): SiteKey =
  var seed = scope & site.len.bigEndStr
  seed.add site
  seed.add n.bigEndStr
  var data = hmac(sha256, pass, seed)
  copyMem addr result[0], addr data.data[0], sizeof SiteKey

template select[T](s: openArray[T], n: char | SomeNumber): T =
  s[n.ord mod s.len]

func getSitePass*(seed: openArray[byte], templates: openArray[string]): string =
  let tmpl = templates.select seed[0]
  for i in 1..tmpl.len:
    result &= (
      case tmpl[i - 1]:
      of 'V': "AEIOU".select seed[i]
      of 'v': "aeiou".select seed[i]
      of 'C': "BCDFGHJKLMNPQRSTVWXYZ".select seed[i]
      of 'c': "bcdfghjklmnpqrstvwxyz".select seed[i]
      of 'A': "AEIOUBCDFGHJKLMNPQRSTVWXYZ".select seed[i]
      of 'a': "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz".select seed[i]
      of 'n': "0123456789".select seed[i]
      of 'o': "@&%?,=[]_:-+*$#!'^~;()/.".select seed[i]
      else: "AEIOUaeiouBCDFGHJKLMNPQRSTVWXYZbcdfghjklmnpqrstvwxyz0123456789!@#$%^&*()".select seed[i]
      )

func getIdenticon*(pass, name: openArray[char]): Identicon =
  let seed = hmac(sha256, pass, name).data
  Identicon(
    leftArm: identiconLeftArms.select seed[0],
    body: identiconBodies.select seed[1],
    rightArm: identiconRightArms.select seed[2],
    accessory: identiconAccessories.select seed[3],
    color: seed[4].uint8 mod 7 + 1
  )
