# masterpassword

[Nim](https://nim-lang.org) implementation of [Master Password algorithm](https://masterpassword.app/masterpassword-algorithm.pdf)

## Installation

`nimble install masterpassword`

Requires `libsodium`

## Example usage

```nim
import masterpassword

let
  mkey = getMasterKey(pass = "The Secret Password", name = "Solitude")
  key = getSiteKey(mkey, "github.com", 1)
  pass = getSitePass(key, templateLong)
```
