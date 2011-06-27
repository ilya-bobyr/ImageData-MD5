load("imageDataMD5.js");

var unitTests = [];


function simpleUnitTest(stringData, expectedMD5)
{
  if (stringData.length % 3 != 0)
  {
    var err = new Error();
    err.message = "stringData value length should always be a multiple of 3.\n"
      + "Got string of length: " + stringData.length;
    throw err;
  }

  var imageData =
  {
    width: stringData.length / 3,
    height: 1,
    data: null
  };

  var data = [];

  for (var i = 0; i < stringData.length; i += 3)
    data.push(
      stringData.charCodeAt(i) & 0xff,
      stringData.charCodeAt(i + 1) & 0xff,
      stringData.charCodeAt(i + 2) & 0xff,
      /* Alpha should be ignored. */
      (i % 0xff - i)
    );

  imageData.data = data;

  var md5 = (new ImageDataMD5(imageData)) + "";

  if (md5!= expectedMD5)
  {
    var err = new Error();
    err.got = md5;
    err.expected = expectedMD5;
    throw err;
  }
}


/*
 * As we should always have our string data length to be a multiple of 3 I have
 * padded all the string that have different lengths with spaces.  This will of
 * cause change their MD5s, but I do not see any other way.  2 tests still test
 * the same values as in the RFC.
 */

function unitTest1()
{
  simpleUnitTest("", "d41d8cd98f00b204e9800998ecf8427e");
}
unitTest1.title = "RFC.1: Empty string";
unitTests.push(unitTest1);


function unitTest2()
{
  simpleUnitTest("a  ", "d4ac0334c4130de05b4a37a87590ccc4");
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
  simpleUnitTest("message digest ", "5c33b66cec053762ad6f2cb06bcd598b");
}
unitTest4.title = "RFC.4: 'message digest'";
unitTests.push(unitTest4);


function unitTest5()
{
  simpleUnitTest("abcdefghijklmnopqrstuvwxyz ",
    "cb20bf9177e73d5ffa71e95d22389d6d");
}
unitTest5.title = "RFC.5: alphabet";
unitTests.push(unitTest5);


function unitTest6()
{
  simpleUnitTest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    + "0123456789 ",
    "009e1cff4fa0bf640ed9b1de7ff6c4a3");
}
unitTest6.title = "RFC.6: alphabet and digits";
unitTests.push(unitTest6);


function unitTest7()
{
  simpleUnitTest("12345678901234567890123456789012345678901234567890123456789"
    + "012345678901234567890 ",
    "d5a01d2d92d9026419f2c4bb5a35b08a");
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

    if (!msg && !got && ! expected)
      msg = JSON.stringify(e);
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
