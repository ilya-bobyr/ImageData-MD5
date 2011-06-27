/*
 * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
 * Digest Algorithm, as defined in RFC 1321.
 * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
 * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
 * Distributed under the BSD License
 * See http://pajhome.org.uk/crypt/md5 for more info.
 */

/*
 * Configurable variables. You may need to tweak these to be compatible with
 * the server-side, but the defaults work in most cases.
 */
var hexcase = 0;   /* hex output format. 0 - lowercase; 1 - uppercase        */
var b64pad  = "";  /* base-64 pad character. "=" for strict RFC compliance   */

/*
 * These are the functions you'll usually want to call
 * They take string arguments and return either hex or base-64 encoded strings
 */
function hex_md5(s)    { return rstr2hex(rstr_md5(str2rstr_utf8(s))); }
function b64_md5(s)    { return rstr2b64(rstr_md5(str2rstr_utf8(s))); }
function any_md5(s, e) { return rstr2any(rstr_md5(str2rstr_utf8(s)), e); }
function hex_hmac_md5(k, d)
  { return rstr2hex(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d))); }
function b64_hmac_md5(k, d)
  { return rstr2b64(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d))); }
function any_hmac_md5(k, d, e)
  { return rstr2any(rstr_hmac_md5(str2rstr_utf8(k), str2rstr_utf8(d)), e); }

/*
 * Perform a simple self-test to see if the VM is working
 */
function md5_vm_test()
{
  return hex_md5("abc").toLowerCase() == "900150983cd24fb0d6963f7d28e17f72";
}

/*
 * Calculate the MD5 of a raw string
 */
function rstr_md5(s)
{
  return binl2rstr(binl_md5(rstr2binl(s), s.length * 8));
}

/*
 * Calculate the HMAC-MD5, of a key and some data (raw strings)
 */
function rstr_hmac_md5(key, data)
{
  var bkey = rstr2binl(key);
  if(bkey.length > 16) bkey = binl_md5(bkey, key.length * 8);

  var ipad = Array(16), opad = Array(16);
  for(var i = 0; i < 16; i++)
  {
    ipad[i] = bkey[i] ^ 0x36363636;
    opad[i] = bkey[i] ^ 0x5C5C5C5C;
  }

  var hash = binl_md5(ipad.concat(rstr2binl(data)), 512 + data.length * 8);
  return binl2rstr(binl_md5(opad.concat(hash), 512 + 128));
}

/*
 * Convert a raw string to a hex string
 */
function rstr2hex(input)
{
  try { hexcase } catch(e) { hexcase=0; }
  var hex_tab = hexcase ? "0123456789ABCDEF" : "0123456789abcdef";
  var output = "";
  var x;
  for(var i = 0; i < input.length; i++)
  {
    x = input.charCodeAt(i);
    output += hex_tab.charAt((x >>> 4) & 0x0F)
           +  hex_tab.charAt( x        & 0x0F);
  }
  return output;
}

/*
 * Convert a raw string to a base-64 string
 */
function rstr2b64(input)
{
  try { b64pad } catch(e) { b64pad=''; }
  var tab = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  var output = "";
  var len = input.length;
  for(var i = 0; i < len; i += 3)
  {
    var triplet = (input.charCodeAt(i) << 16)
                | (i + 1 < len ? input.charCodeAt(i+1) << 8 : 0)
                | (i + 2 < len ? input.charCodeAt(i+2)      : 0);
    for(var j = 0; j < 4; j++)
    {
      if(i * 8 + j * 6 > input.length * 8) output += b64pad;
      else output += tab.charAt((triplet >>> 6*(3-j)) & 0x3F);
    }
  }
  return output;
}

/*
 * Convert a raw string to an arbitrary string encoding
 */
function rstr2any(input, encoding)
{
  var divisor = encoding.length;
  var i, j, q, x, quotient;

  /* Convert to an array of 16-bit big-endian values, forming the dividend */
  var dividend = Array(Math.ceil(input.length / 2));
  for(i = 0; i < dividend.length; i++)
  {
    dividend[i] = (input.charCodeAt(i * 2) << 8) | input.charCodeAt(i * 2 + 1);
  }

  /*
   * Repeatedly perform a long division. The binary array forms the dividend,
   * the length of the encoding is the divisor. Once computed, the quotient
   * forms the dividend for the next step. All remainders are stored for later
   * use.
   */
  var full_length = Math.ceil(input.length * 8 /
                                    (Math.log(encoding.length) / Math.log(2)));
  var remainders = Array(full_length);
  for(j = 0; j < full_length; j++)
  {
    quotient = Array();
    x = 0;
    for(i = 0; i < dividend.length; i++)
    {
      x = (x << 16) + dividend[i];
      q = Math.floor(x / divisor);
      x -= q * divisor;
      if(quotient.length > 0 || q > 0)
        quotient[quotient.length] = q;
    }
    remainders[j] = x;
    dividend = quotient;
  }

  /* Convert the remainders to the output string */
  var output = "";
  for(i = remainders.length - 1; i >= 0; i--)
    output += encoding.charAt(remainders[i]);

  return output;
}

/*
 * Encode a string as utf-8.
 * For efficiency, this assumes the input is valid utf-16.
 */
function str2rstr_utf8(input)
{
  var output = "";
  var i = -1;
  var x, y;

  while(++i < input.length)
  {
    /* Decode utf-16 surrogate pairs */
    x = input.charCodeAt(i);
    y = i + 1 < input.length ? input.charCodeAt(i + 1) : 0;
    if(0xD800 <= x && x <= 0xDBFF && 0xDC00 <= y && y <= 0xDFFF)
    {
      x = 0x10000 + ((x & 0x03FF) << 10) + (y & 0x03FF);
      i++;
    }

    /* Encode output as utf-8 */
    if(x <= 0x7F)
      output += String.fromCharCode(x);
    else if(x <= 0x7FF)
      output += String.fromCharCode(0xC0 | ((x >>> 6 ) & 0x1F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0xFFFF)
      output += String.fromCharCode(0xE0 | ((x >>> 12) & 0x0F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
    else if(x <= 0x1FFFFF)
      output += String.fromCharCode(0xF0 | ((x >>> 18) & 0x07),
                                    0x80 | ((x >>> 12) & 0x3F),
                                    0x80 | ((x >>> 6 ) & 0x3F),
                                    0x80 | ( x         & 0x3F));
  }
  return output;
}

/*
 * Encode a string as utf-16
 */
function str2rstr_utf16le(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode( input.charCodeAt(i)        & 0xFF,
                                  (input.charCodeAt(i) >>> 8) & 0xFF);
  return output;
}

function str2rstr_utf16be(input)
{
  var output = "";
  for(var i = 0; i < input.length; i++)
    output += String.fromCharCode((input.charCodeAt(i) >>> 8) & 0xFF,
                                   input.charCodeAt(i)        & 0xFF);
  return output;
}

/*
 * Convert a raw string to an array of little-endian words
 * Characters >255 have their high-byte silently ignored.
 */
function rstr2binl(input)
{
  var output = Array(input.length >> 2);
  for(var i = 0; i < output.length; i++)
    output[i] = 0;
  for(var i = 0; i < input.length * 8; i += 8)
    output[i>>5] |= (input.charCodeAt(i / 8) & 0xFF) << (i%32);
  return output;
}

/*
 * Convert an array of little-endian words to a string
 */
function binl2rstr(input)
{
  var output = "";
  for(var i = 0; i < input.length * 32; i += 8)
    output += String.fromCharCode((input[i>>5] >>> (i % 32)) & 0xFF);
  return output;
}

/*
 * Calculate the MD5 of an array of little-endian words, and a bit length.
 */
function binl_md5(x, len)
{
  /* append padding */
  x[len >> 5] |= 0x80 << ((len) % 32);
  x[(((len + 64) >>> 9) << 4) + 14] = len;

  print(x.length + ": " + JSON.stringify(x));

  var a = 0x67452301;
  var b = 0xefcdab89;
  var c = 0x98badcfe;
  var d = 0x10325476;

  for(var i = 0; i < x.length; i += 16)
  {
    var olda = a;
    var oldb = b;
    var oldc = c;
    var oldd = d;

    print("a: " + a);
    print("b: " + b);
    print("c: " + c);
    print("d: " + d);

    a = md5_ff(a, b, c, d, x[i+ 0], 7 , 0xd76aa478);
    d = md5_ff(d, a, b, c, x[i+ 1], 12, 0xe8c7b756);
    c = md5_ff(c, d, a, b, x[i+ 2], 17, 0x242070db);
    b = md5_ff(b, c, d, a, x[i+ 3], 22, 0xc1bdceee);
    a = md5_ff(a, b, c, d, x[i+ 4], 7 , 0xf57c0faf);
    d = md5_ff(d, a, b, c, x[i+ 5], 12, 0x4787c62a);
    c = md5_ff(c, d, a, b, x[i+ 6], 17, 0xa8304613);
    b = md5_ff(b, c, d, a, x[i+ 7], 22, 0xfd469501);
    a = md5_ff(a, b, c, d, x[i+ 8], 7 , 0x698098d8);
    d = md5_ff(d, a, b, c, x[i+ 9], 12, 0x8b44f7af);
    c = md5_ff(c, d, a, b, x[i+10], 17, 0xffff5bb1);
    b = md5_ff(b, c, d, a, x[i+11], 22, 0x895cd7be);
    a = md5_ff(a, b, c, d, x[i+12], 7 , 0x6b901122);
    d = md5_ff(d, a, b, c, x[i+13], 12, 0xfd987193);
    c = md5_ff(c, d, a, b, x[i+14], 17, 0xa679438e);
    b = md5_ff(b, c, d, a, x[i+15], 22, 0x49b40821);

    a = md5_gg(a, b, c, d, x[i+ 1], 5 , 0xf61e2562);
    d = md5_gg(d, a, b, c, x[i+ 6], 9 , 0xc040b340);
    c = md5_gg(c, d, a, b, x[i+11], 14, 0x265e5a51);
    b = md5_gg(b, c, d, a, x[i+ 0], 20, 0xe9b6c7aa);
    a = md5_gg(a, b, c, d, x[i+ 5], 5 , 0xd62f105d);
    d = md5_gg(d, a, b, c, x[i+10], 9 ,  0x2441453);
    c = md5_gg(c, d, a, b, x[i+15], 14, 0xd8a1e681);
    b = md5_gg(b, c, d, a, x[i+ 4], 20, 0xe7d3fbc8);
    a = md5_gg(a, b, c, d, x[i+ 9], 5 , 0x21e1cde6);
    d = md5_gg(d, a, b, c, x[i+14], 9 , 0xc33707d6);
    c = md5_gg(c, d, a, b, x[i+ 3], 14, 0xf4d50d87);
    b = md5_gg(b, c, d, a, x[i+ 8], 20, 0x455a14ed);
    a = md5_gg(a, b, c, d, x[i+13], 5 , 0xa9e3e905);
    d = md5_gg(d, a, b, c, x[i+ 2], 9 , 0xfcefa3f8);
    c = md5_gg(c, d, a, b, x[i+ 7], 14, 0x676f02d9);
    b = md5_gg(b, c, d, a, x[i+12], 20, 0x8d2a4c8a);

    a = md5_hh(a, b, c, d, x[i+ 5], 4 , 0xfffa3942);
    d = md5_hh(d, a, b, c, x[i+ 8], 11, 0x8771f681);
    c = md5_hh(c, d, a, b, x[i+11], 16, 0x6d9d6122);
    b = md5_hh(b, c, d, a, x[i+14], 23, 0xfde5380c);
    a = md5_hh(a, b, c, d, x[i+ 1], 4 , 0xa4beea44);
    d = md5_hh(d, a, b, c, x[i+ 4], 11, 0x4bdecfa9);
    c = md5_hh(c, d, a, b, x[i+ 7], 16, 0xf6bb4b60);
    b = md5_hh(b, c, d, a, x[i+10], 23, 0xbebfbc70);
    a = md5_hh(a, b, c, d, x[i+13], 4 , 0x289b7ec6);
    d = md5_hh(d, a, b, c, x[i+ 0], 11, 0xeaa127fa);
    c = md5_hh(c, d, a, b, x[i+ 3], 16, 0xd4ef3085);
    b = md5_hh(b, c, d, a, x[i+ 6], 23,  0x4881d05);
    a = md5_hh(a, b, c, d, x[i+ 9], 4 , 0xd9d4d039);
    d = md5_hh(d, a, b, c, x[i+12], 11, 0xe6db99e5);
    c = md5_hh(c, d, a, b, x[i+15], 16, 0x1fa27cf8);
    b = md5_hh(b, c, d, a, x[i+ 2], 23, 0xc4ac5665);

    a = md5_ii(a, b, c, d, x[i+ 0], 6 , 0xf4292244);
    d = md5_ii(d, a, b, c, x[i+ 7], 10, 0x432aff97);
    c = md5_ii(c, d, a, b, x[i+14], 15, 0xab9423a7);
    b = md5_ii(b, c, d, a, x[i+ 5], 21, 0xfc93a039);
    a = md5_ii(a, b, c, d, x[i+12], 6 , 0x655b59c3);
    d = md5_ii(d, a, b, c, x[i+ 3], 10, 0x8f0ccc92);
    c = md5_ii(c, d, a, b, x[i+10], 15, 0xffeff47d);
    b = md5_ii(b, c, d, a, x[i+ 1], 21, 0x85845dd1);
    a = md5_ii(a, b, c, d, x[i+ 8], 6 , 0x6fa87e4f);
    d = md5_ii(d, a, b, c, x[i+15], 10, 0xfe2ce6e0);
    c = md5_ii(c, d, a, b, x[i+ 6], 15, 0xa3014314);
    b = md5_ii(b, c, d, a, x[i+13], 21, 0x4e0811a1);
    a = md5_ii(a, b, c, d, x[i+ 4], 6 , 0xf7537e82);
    d = md5_ii(d, a, b, c, x[i+11], 10, 0xbd3af235);
    c = md5_ii(c, d, a, b, x[i+ 2], 15, 0x2ad7d2bb);
    b = md5_ii(b, c, d, a, x[i+ 9], 21, 0xeb86d391);

    a = safe_add(a, olda);
    b = safe_add(b, oldb);
    c = safe_add(c, oldc);
    d = safe_add(d, oldd);

    print("a: " + a);
    print("b: " + b);
    print("c: " + c);
    print("d: " + d);
  }
  return Array(a, b, c, d);
}

/*
 * These functions implement the four basic operations the algorithm uses.
 */
function md5_cmn(q, a, b, x, s, t)
{
  return safe_add(bit_rol(safe_add(safe_add(a, q), safe_add(x, t)), s),b);
}
function md5_ff(a, b, c, d, x, s, t)
{
  return md5_cmn((b & c) | ((~b) & d), a, b, x, s, t);
}
function md5_gg(a, b, c, d, x, s, t)
{
  return md5_cmn((b & d) | (c & (~d)), a, b, x, s, t);
}
function md5_hh(a, b, c, d, x, s, t)
{
  return md5_cmn(b ^ c ^ d, a, b, x, s, t);
}
function md5_ii(a, b, c, d, x, s, t)
{
  return md5_cmn(c ^ (b | (~d)), a, b, x, s, t);
}

/*
 * Add integers, wrapping at 2^32. This uses 16-bit operations internally
 * to work around bugs in some JS interpreters.
 */
function safe_add(x, y)
{
  var lsw = (x & 0xFFFF) + (y & 0xFFFF);
  var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
  return (msw << 16) | (lsw & 0xFFFF);
}

/*
 * Bitwise rotate a 32-bit number to the left.
 */
function bit_rol(num, cnt)
{
  return (num << cnt) | (num >>> (32 - cnt));
}

/* vim: set et sts=2 sw=2 tw=80 spell spl=en: */
