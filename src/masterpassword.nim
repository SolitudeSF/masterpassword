import endians
import hmac

when defined(windows):
  const libsodiumFn = "libsodium.dll"
elif defined(macosx):
  const libsodiumFn = "libsodium.dylib"
else:
  const libsodiumFn = "libsodium.so(|.18|.23)"

proc scrypt(
  passwd: ptr cuchar, passwdlen: csize,
  salt: ptr cuchar, saltlen: csize,
  n: culonglong, r, p: cuint,
  buf: ptr cuchar, buflen: csize
): cint {.importc: "crypto_pwhash_scryptsalsa208sha256_ll", dynlib: libsodiumFn.}

proc sodium_init: cint {.importc, dynlib: libsodiumFn.}

type Identicon* = object
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

proc init* =
  if sodiumInit() != 0:
    raise newException(CatchableError, "Failed to initialize libsodium")

proc genMasterKey(pass, salt: string, n: uint64, r, p: uint32, l: uint): string =
  result = newString(l)
  if scrypt(
    cast[ptr cuchar](pass.cstring), pass.len.csize,
    cast[ptr cuchar](salt.cstring), salt.len.csize,
    n.culonglong, r.cuint, p.cuint,
    cast[ptr cuchar](result.cstring), l.csize
  ) != 0: raise newException(CatchableError, "Call to libsodium failed")

func bigEndStr(i: SomeNumber): string =
  result = newString 4
  var i = i
  bigEndian32 addr result[0], addr i

proc getMasterKey*(pass, name: string, scope = scopePrefix): string =
  genMasterKey(pass, scope & name.len.bigEndStr & name, 32768, 8, 2, 64)

proc getSiteKey*(pass, site: string, n = 1, scope = scopePrefix): string =
  result = newString 32
  let seed = scope & site.len.bigEndStr & site & n.bigEndStr
  var data = hmac_sha256(pass, seed)
  copyMem addr result[0], addr data[0], 32

template select[T](s: openArray[T], n: char | SomeNumber): T =
  s[n.ord mod s.len]

proc getSitePass*(seed: string, templates: openArray[string]): string =
  let tmpl = templates.select seed[0]
  for i in 1..tmpl.len:
    result &= (case tmpl[i - 1]:
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

func getIdenticon*(pass, name: string): Identicon =
  let seed = hmac_sha256(pass, name)
  Identicon(
    leftArm: identiconLeftArms.select seed[0],
    body: identiconBodies.select seed[1],
    rightArm: identiconRightArms.select seed[2],
    accessory: identiconAccessories.select seed[3],
    color: seed[4].uint8 mod 7 + 1
  )

init()
