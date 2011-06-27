load("md5.js");

var unitTests = [];


function simpleUnitTest(data, expectedMD5)
{
  var md5 = hex_md5(data).toLowerCase();

  if (md5 != expectedMD5)
  {
    var err = new Error();
    err.got = md5;
    err.expected = expectedMD5;
    throw err;
  }
}


function unitTest1()
{
  simpleUnitTest("", "d41d8cd98f00b204e9800998ecf8427e");
}
unitTest1.title = "RFC.1: Empty string";
unitTests.push(unitTest1);

function unitTest2()
{
  simpleUnitTest("a", "0cc175b9c0f1b6a831c399e269772661");
}
unitTest2.title = "RFC.2: 'a'";
unitTests.push(unitTest2);


function unitTest3()
{
  simpleUnitTest("abc", "900150983cd24fb0d6963f7d28e17f72");
}
unitTest3.title = "RFC.3: 'abc'";
unitTests.push(unitTest3);


function unitTest4()
{
  simpleUnitTest("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
}
unitTest4.title = "RFC.4: 'message digest'";
unitTests.push(unitTest4);


function unitTest5()
{
  simpleUnitTest("abcdefghijklmnopqrstuvwxyz",
    "c3fcd3d76192e4007dfb496cca67e13b");
}
unitTest5.title = "RFC.5: alphabet";
unitTests.push(unitTest5);


function unitTest6()
{
  simpleUnitTest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    + "0123456789",
    "d174ab98d277d9f5a5611c2c9f419d9f");
}
unitTest6.title = "RFC.6: alphabet and digits";
unitTests.push(unitTest6);


function unitTest7()
{
  simpleUnitTest("12345678901234567890123456789012345678901234567890123456789"
    + "012345678901234567890",
    "57edf4a22be3c955ac49da2e2107b67a");
  }
unitTest7.title = "RFC.7: lots of digits";
unitTests.push(unitTest7);


print("Unit tests:");
for (var i = 0; i < unitTests.length; ++i)
{
  var failed = true;
  var msg, got, expected;
  try
  {
    unitTests[i]();
    failed = false;
  }
  catch (e)
  {
    msg = e.message;
    got = e.got;
    expected = e.expected;
  }

  print(i + ". " + unitTests[i].title + " : " + (!failed ? "OK" : "fail"));

  if (failed)
  {
    if (msg)
      print("  " + msg);
    if (got)
      print("Got: " + JSON.stringify(got, null, 2));
    if (expected)
      print("Expected: " + JSON.stringify(expected, null, 2));
  }
}

/* vim: set et sts=2 sw=2 tw=80 spell spl=en: */
