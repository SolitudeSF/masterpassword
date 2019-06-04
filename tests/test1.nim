import ../src/masterpassword
import unittest

suite "PasswordGen":

  test "Pin":
    let
      mkey = getMasterKey("Correct Horse Battery Staple", "Cosima Niehaus")
      key = getSiteKey(mkey, "bank.com", 1)
      pass = getSitePass(key, templatePin)

    check(pass == "7404")

  test "Long":
    let
      mkey = getMasterKey("Correct Horse Battery Staple", "Cosima Niehaus")
      key = getSiteKey(mkey, "twitter.com", 5)
      pass = getSitePass(key, templateLong)

    check(pass == "Kiwe2^BecuRodw")

  test "Maximum":
    let
      mkey = getMasterKey("hunter2", "UserName")
      key = getSiteKey(mkey, "test", 1)
      pass = getSitePass(key, templateMaximum)

    check(pass == "e5:kl#V@0uAZ02xKUic5")

  test "Icon":
    let
      pass = "pass"
      name = "name"
      icon = getIdenticon(pass, name)

    check(icon == Identicon(leftArm: "╔", body: "☺", rightArm: "╗", accessory: "♫", color: 6))
