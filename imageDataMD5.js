"use strict;"

/*
 * Calculates and MD5 of the pixels color data.  Skips alpha channel values.
 * The calculation is performed during construction of the object.
 */
function ImageDataMD5(imageData)
{
  this._md5 = imageData ?
      this._wordsToMD5(this._imageDataToWords(imageData))
    :
      null;
}

ImageDataMD5.prototype =
{
  copy: function ()
  {
    var r = new ImageDataMD5(null);
    r._md5 = this._md5;
    return r;
  },

  get md5()
  {
    return this._md5;
  },

  toString: function ()
  {
    var hex = "0123456789abcdef";
    var r = "";

    for (var i = 0; i < this._md5.length; ++i)
    {
      var word = this._md5[i];
      r += hex.charAt((word >>>  4) & 0x0F)
        +  hex.charAt((word >>>  0) & 0x0F)
        +  hex.charAt((word >>> 12) & 0x0F)
        +  hex.charAt((word >>>  8) & 0x0F)
        +  hex.charAt((word >>> 20) & 0x0F)
        +  hex.charAt((word >>> 16) & 0x0F)
        +  hex.charAt((word >>> 28) & 0x0F)
        +  hex.charAt((word >>> 24) & 0x0F);
    }

    return r;
  },

  equal: function (rhs)
  {
    if (rhs instanceof ImageDataMD5)
      return this._md5[0] == rhs._md5[0]
          && this._md5[1] == rhs._md5[1]
          && this._md5[2] == rhs._md5[2]
          && this._md5[3] == rhs._md5[3];

    return "" + this == "" + rhs;
  },

  /*
   * === Implementation ===
   */

  /*
   * MD5 implementation taken from http://pajhome.org.uk/crypt/md5/index.html
   *
   * Slightly modified to work with imageData source.
   */

  /*
   * A JavaScript implementation of the RSA Data Security, Inc. MD5 Message
   * Digest Algorithm, as defined in RFC 1321.
   * Version 2.2 Copyright (C) Paul Johnston 1999 - 2009
   * Other contributors: Greg Holt, Andrew Kepert, Ydnar, Lostinet
   * Distributed under the BSD License
   * See http://pajhome.org.uk/crypt/md5 for more info.
   */

  /*
   * Convert an imageData pixel color data to a sequence of 16-word blocks,
   * stored as an array.
   * Append padding bits and the length, as described in the MD5 standard.
   */
  _imageDataToWords: function (imageData)
  {
    var width = imageData.width;
    var height = imageData.height;
    var data = imageData.data;

    var pixelSize = width * height;
    /* We have 3 color bytes per pixel. */
    var byteSize = pixelSize * 3;

    /*
     * 4 bytes in a 32-bit word.
     * We also need to pad.  Padding adds at least 1 bit and at most 512 bits
     * (16 32-bit words), such that the number of bits in the message becomes
     * congruent to 448, modulo 512.  That is 56 modulo 64 in bytes.
     * Then there is a 2 32-bit word length.
     * Total message length is always a multiple of 512 in bits, 64 in bytes or
     * 16 in 32-bit words.
     *
     * In other words we are going to add 8 bytes for the length and 1 byte
     * that marks the message end.  It means that 9 bytes at the end will always
     * be used.  The rest is padding.
     *
     * 1 byte for the end of message marker and 3 to round up.
     */
    var wordsForDataAndFinalBit = (byteSize + 4) >>> 2;
    /*
     * Plus 2 words for length and 15 to round up to the nearest integer that is
     * a multiple of 16.
     */
    var words = new Array((wordsForDataAndFinalBit + 17) & ~15);

    for (var i = 0; i < words.length; ++i)
      words[i] = 0;

    var i = 0;
    var bitSize = byteSize * 8;
    /*
     * i is in bits.  I guess, it is a little faster this way as we skip
     * one multiplication later in the loop body.
     */
    for ( ; i < bitSize; i += 8)
    {
      /*
       * We skip bytes that contain alpha values of the pixels, that is every
       * forth byte in the data array.
       * { 0, 1, 2, 3, 4, ... } -> { 0, 1, 2, 4, 5, ... }
       *
       * i >>> 1 = (i / 8) * 4.
       * (... >>> 0) converts into an unsigned 32-bit.
       */
      var pixelIndex = ((i >>> 1) / 3) >>> 0;
      words[i >>> 5] |= data[pixelIndex] << (i % 32);
    }

    /* One bit after the last message bit is always set. */
    words[i >>> 5] |= 0x80 << (i % 32);

    /* And a length in bits as a 64 bit number split in to 32-bit words. */
    words[words.length - 2] = (byteSize & 0x1fffffff) << 3;
    words[words.length - 1] = byteSize >>> 29;

    return words;
  },

  /*
   * These functions implement the four basic operations the algorithm uses.
   */
  _commonOp: function (q, a, b, x, s, t)
  {
    var sum = this._safeAdd(this._safeAdd(a, q), this._safeAdd(x, t));
    return this._safeAdd(this._bitRol(sum, s), b);
  },

  _F: function (a, b, c, d, x, s, t)
  {
    return this._commonOp((b & c) | ((~b) & d), a, b, x, s, t);
  },

  _G: function (a, b, c, d, x, s, t)
  {
    return this._commonOp((b & d) | (c & (~d)), a, b, x, s, t);
  },

  _H: function (a, b, c, d, x, s, t)
  {
    return this._commonOp(b ^ c ^ d, a, b, x, s, t);
  },

  _I: function (a, b, c, d, x, s, t)
  {
    return this._commonOp(c ^ (b | (~d)), a, b, x, s, t);
  },

  /*
   * Bitwise rotate a 32-bit number to the left
   */
  _bitRol: function (num, cnt)
  {
    return (num << cnt) | (num >>> (32 - cnt));
  },

  _safeAdd: function (x, y)
  {
    var lsw = (x & 0xFFFF) + (y & 0xFFFF);
    var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
  },

  /*
   * Calculate the MD5 of an array of little-endian words as produced by
   * _imageDataToWords().
   */
  _wordsToMD5: function (x)
  {
    var a = 0x67452301;
    var b = 0xefcdab89;
    var c = 0x98badcfe;
    var d = 0x10325476;

    for (var i = 0; i < x.length; i += 16)
    {
      var olda = a;
      var oldb = b;
      var oldc = c;
      var oldd = d;

      a = this._F(a, b, c, d, x[i+ 0], 7 , 0xd76aa478);
      d = this._F(d, a, b, c, x[i+ 1], 12, 0xe8c7b756);
      c = this._F(c, d, a, b, x[i+ 2], 17, 0x242070db);
      b = this._F(b, c, d, a, x[i+ 3], 22, 0xc1bdceee);
      a = this._F(a, b, c, d, x[i+ 4], 7 , 0xf57c0faf);
      d = this._F(d, a, b, c, x[i+ 5], 12, 0x4787c62a);
      c = this._F(c, d, a, b, x[i+ 6], 17, 0xa8304613);
      b = this._F(b, c, d, a, x[i+ 7], 22, 0xfd469501);
      a = this._F(a, b, c, d, x[i+ 8], 7 , 0x698098d8);
      d = this._F(d, a, b, c, x[i+ 9], 12, 0x8b44f7af);
      c = this._F(c, d, a, b, x[i+10], 17, 0xffff5bb1);
      b = this._F(b, c, d, a, x[i+11], 22, 0x895cd7be);
      a = this._F(a, b, c, d, x[i+12], 7 , 0x6b901122);
      d = this._F(d, a, b, c, x[i+13], 12, 0xfd987193);
      c = this._F(c, d, a, b, x[i+14], 17, 0xa679438e);
      b = this._F(b, c, d, a, x[i+15], 22, 0x49b40821);

      a = this._G(a, b, c, d, x[i+ 1], 5 , 0xf61e2562);
      d = this._G(d, a, b, c, x[i+ 6], 9 , 0xc040b340);
      c = this._G(c, d, a, b, x[i+11], 14, 0x265e5a51);
      b = this._G(b, c, d, a, x[i+ 0], 20, 0xe9b6c7aa);
      a = this._G(a, b, c, d, x[i+ 5], 5 , 0xd62f105d);
      d = this._G(d, a, b, c, x[i+10], 9 ,  0x2441453);
      c = this._G(c, d, a, b, x[i+15], 14, 0xd8a1e681);
      b = this._G(b, c, d, a, x[i+ 4], 20, 0xe7d3fbc8);
      a = this._G(a, b, c, d, x[i+ 9], 5 , 0x21e1cde6);
      d = this._G(d, a, b, c, x[i+14], 9 , 0xc33707d6);
      c = this._G(c, d, a, b, x[i+ 3], 14, 0xf4d50d87);
      b = this._G(b, c, d, a, x[i+ 8], 20, 0x455a14ed);
      a = this._G(a, b, c, d, x[i+13], 5 , 0xa9e3e905);
      d = this._G(d, a, b, c, x[i+ 2], 9 , 0xfcefa3f8);
      c = this._G(c, d, a, b, x[i+ 7], 14, 0x676f02d9);
      b = this._G(b, c, d, a, x[i+12], 20, 0x8d2a4c8a);

      a = this._H(a, b, c, d, x[i+ 5], 4 , 0xfffa3942);
      d = this._H(d, a, b, c, x[i+ 8], 11, 0x8771f681);
      c = this._H(c, d, a, b, x[i+11], 16, 0x6d9d6122);
      b = this._H(b, c, d, a, x[i+14], 23, 0xfde5380c);
      a = this._H(a, b, c, d, x[i+ 1], 4 , 0xa4beea44);
      d = this._H(d, a, b, c, x[i+ 4], 11, 0x4bdecfa9);
      c = this._H(c, d, a, b, x[i+ 7], 16, 0xf6bb4b60);
      b = this._H(b, c, d, a, x[i+10], 23, 0xbebfbc70);
      a = this._H(a, b, c, d, x[i+13], 4 , 0x289b7ec6);
      d = this._H(d, a, b, c, x[i+ 0], 11, 0xeaa127fa);
      c = this._H(c, d, a, b, x[i+ 3], 16, 0xd4ef3085);
      b = this._H(b, c, d, a, x[i+ 6], 23,  0x4881d05);
      a = this._H(a, b, c, d, x[i+ 9], 4 , 0xd9d4d039);
      d = this._H(d, a, b, c, x[i+12], 11, 0xe6db99e5);
      c = this._H(c, d, a, b, x[i+15], 16, 0x1fa27cf8);
      b = this._H(b, c, d, a, x[i+ 2], 23, 0xc4ac5665);

      a = this._I(a, b, c, d, x[i+ 0], 6 , 0xf4292244);
      d = this._I(d, a, b, c, x[i+ 7], 10, 0x432aff97);
      c = this._I(c, d, a, b, x[i+14], 15, 0xab9423a7);
      b = this._I(b, c, d, a, x[i+ 5], 21, 0xfc93a039);
      a = this._I(a, b, c, d, x[i+12], 6 , 0x655b59c3);
      d = this._I(d, a, b, c, x[i+ 3], 10, 0x8f0ccc92);
      c = this._I(c, d, a, b, x[i+10], 15, 0xffeff47d);
      b = this._I(b, c, d, a, x[i+ 1], 21, 0x85845dd1);
      a = this._I(a, b, c, d, x[i+ 8], 6 , 0x6fa87e4f);
      d = this._I(d, a, b, c, x[i+15], 10, 0xfe2ce6e0);
      c = this._I(c, d, a, b, x[i+ 6], 15, 0xa3014314);
      b = this._I(b, c, d, a, x[i+13], 21, 0x4e0811a1);
      a = this._I(a, b, c, d, x[i+ 4], 6 , 0xf7537e82);
      d = this._I(d, a, b, c, x[i+11], 10, 0xbd3af235);
      c = this._I(c, d, a, b, x[i+ 2], 15, 0x2ad7d2bb);
      b = this._I(b, c, d, a, x[i+ 9], 21, 0xeb86d391);

      a = this._safeAdd(a, olda);
      b = this._safeAdd(b, oldb);
      c = this._safeAdd(c, oldc);
      d = this._safeAdd(d, oldd);
    }
    return [ a, b, c, d ];
  },

};

/* vim: set et sts=2 sw=2 tw=80 spell spl=en: */
