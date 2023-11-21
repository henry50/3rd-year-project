/*

    Cloudflare OPAQUE 0.7.4 client

Copyright (c) 2021 Cloudflare, Inc. and contributors.
Copyright (c) 2021 Cloudflare, Inc.
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

*/

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
function joinAll$1(a) {
    let size = 0;
    for (let i = 0; i < a.length; i++) {
        size += a[i].length;
    }
    const ret = new Uint8Array(new ArrayBuffer(size));
    for (let i = 0, offset = 0; i < a.length; i++) {
        ret.set(a[i], offset);
        offset += a[i].length;
    }
    return ret;
}
function xor$1(a, b) {
    if (a.length !== b.length || a.length === 0) {
        throw new Error('arrays of different length');
    }
    const n = a.length, c = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
        c[i] = a[i] ^ b[i];
    }
    return c;
}
function ctEqual$1(a, b) {
    if (a.length !== b.length || a.length === 0) {
        return false;
    }
    const n = a.length;
    let c = 0;
    for (let i = 0; i < n; i++) {
        c |= a[i] ^ b[i];
    }
    return c === 0;
}
function to16bits(n) {
    if (!(n >= 0 && n < 0xffff)) {
        throw new Error('number bigger than 2^16');
    }
    return new Uint8Array([(n >> 8) & 0xff, n & 0xff]);
}
function hashParams(hash) {
    switch (hash) {
        case 'SHA-1':
            return { outLenBytes: 20, blockLenBytes: 64 };
        case 'SHA-256':
            return { outLenBytes: 32, blockLenBytes: 64 };
        case 'SHA-384':
            return { outLenBytes: 48, blockLenBytes: 128 };
        case 'SHA-512':
            return { outLenBytes: 64, blockLenBytes: 128 };
        default:
            throw new Error(`invalid hash name: ${hash}`);
    }
}

/** @fileOverview Javascript cryptography implementation.
 *
 * Crush to remove comments, shorten variable names and
 * generally reduce transmission size.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/*jslint indent: 2, bitwise: false, nomen: false, plusplus: false, white: false, regexp: false */
/*global document, window, escape, unescape, module, require, Uint32Array */
/**
 * The Stanford Javascript Crypto Library, top-level namespace.
 * @namespace
 */
var sjcl = {
    /**
     * Symmetric ciphers.
     * @namespace
     */
    cipher: {},
    /**
     * Hash functions.  Right now only SHA256 is implemented.
     * @namespace
     */
    hash: {},
    /**
     * Key exchange functions.  Right now only SRP is implemented.
     * @namespace
     */
    keyexchange: {},
    /**
     * Cipher modes of operation.
     * @namespace
     */
    mode: {},
    /**
     * Miscellaneous.  HMAC and PBKDF2.
     * @namespace
     */
    misc: {},
    /**
     * Bit array encoders and decoders.
     * @namespace
     *
     * @description
     * The members of this namespace are functions which translate between
     * SJCL's bitArrays and other objects (usually strings).  Because it
     * isn't always clear which direction is encoding and which is decoding,
     * the method names are "fromBits" and "toBits".
     */
    codec: {},
    /**
     * Exceptions.
     * @namespace
     */
    exception: {
        /**
         * Ciphertext is corrupt.
         * @constructor
         */
        corrupt: function (message) {
            this.toString = function () { return "CORRUPT: " + this.message; };
            this.message = message;
        },
        /**
         * Invalid parameter.
         * @constructor
         */
        invalid: function (message) {
            this.toString = function () { return "INVALID: " + this.message; };
            this.message = message;
        },
        /**
         * Bug or missing feature in SJCL.
         * @constructor
         */
        bug: function (message) {
            this.toString = function () { return "BUG: " + this.message; };
            this.message = message;
        },
        /**
         * Something isn't ready.
         * @constructor
         */
        notReady: function (message) {
            this.toString = function () { return "NOT READY: " + this.message; };
            this.message = message;
        }
    }
};
/** @fileOverview Low-level AES implementation.
 *
 * This file contains a low-level implementation of AES, optimized for
 * size and for efficiency on several browsers.  It is based on
 * OpenSSL's aes_core.c, a public-domain implementation by Vincent
 * Rijmen, Antoon Bosselaers and Paulo Barreto.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/**
 * Schedule out an AES key for both encryption and decryption.  This
 * is a low-level class.  Use a cipher mode to do bulk encryption.
 *
 * @constructor
 * @param {Array} key The key as an array of 4, 6 or 8 words.
 */
sjcl.cipher.aes = function (key) {
    if (!this._tables[0][0][0]) {
        this._precompute();
    }
    var i, j, tmp, encKey, decKey, sbox = this._tables[0][4], decTable = this._tables[1], keyLen = key.length, rcon = 1;
    if (keyLen !== 4 && keyLen !== 6 && keyLen !== 8) {
        throw new sjcl.exception.invalid("invalid aes key size");
    }
    this._key = [encKey = key.slice(0), decKey = []];
    // schedule encryption keys
    for (i = keyLen; i < 4 * keyLen + 28; i++) {
        tmp = encKey[i - 1];
        // apply sbox
        if (i % keyLen === 0 || (keyLen === 8 && i % keyLen === 4)) {
            tmp = sbox[tmp >>> 24] << 24 ^ sbox[tmp >> 16 & 255] << 16 ^ sbox[tmp >> 8 & 255] << 8 ^ sbox[tmp & 255];
            // shift rows and add rcon
            if (i % keyLen === 0) {
                tmp = tmp << 8 ^ tmp >>> 24 ^ rcon << 24;
                rcon = rcon << 1 ^ (rcon >> 7) * 283;
            }
        }
        encKey[i] = encKey[i - keyLen] ^ tmp;
    }
    // schedule decryption keys
    for (j = 0; i; j++, i--) {
        tmp = encKey[j & 3 ? i : i - 4];
        if (i <= 4 || j < 4) {
            decKey[j] = tmp;
        }
        else {
            decKey[j] = decTable[0][sbox[tmp >>> 24]] ^
                decTable[1][sbox[tmp >> 16 & 255]] ^
                decTable[2][sbox[tmp >> 8 & 255]] ^
                decTable[3][sbox[tmp & 255]];
        }
    }
};
sjcl.cipher.aes.prototype = {
    // public
    /* Something like this might appear here eventually
    name: "AES",
    blockSize: 4,
    keySizes: [4,6,8],
    */
    /**
     * Encrypt an array of 4 big-endian words.
     * @param {Array} data The plaintext.
     * @return {Array} The ciphertext.
     */
    encrypt: function (data) { return this._crypt(data, 0); },
    /**
     * Decrypt an array of 4 big-endian words.
     * @param {Array} data The ciphertext.
     * @return {Array} The plaintext.
     */
    decrypt: function (data) { return this._crypt(data, 1); },
    /**
     * The expanded S-box and inverse S-box tables.  These will be computed
     * on the client so that we don't have to send them down the wire.
     *
     * There are two tables, _tables[0] is for encryption and
     * _tables[1] is for decryption.
     *
     * The first 4 sub-tables are the expanded S-box with MixColumns.  The
     * last (_tables[01][4]) is the S-box itself.
     *
     * @private
     */
    _tables: [[[], [], [], [], []], [[], [], [], [], []]],
    /**
     * Expand the S-box tables.
     *
     * @private
     */
    _precompute: function () {
        var encTable = this._tables[0], decTable = this._tables[1], sbox = encTable[4], sboxInv = decTable[4], i, x, xInv, d = [], th = [], x2, x4, x8, s, tEnc, tDec;
        // Compute double and third tables
        for (i = 0; i < 256; i++) {
            th[(d[i] = i << 1 ^ (i >> 7) * 283) ^ i] = i;
        }
        for (x = xInv = 0; !sbox[x]; x ^= x2 || 1, xInv = th[xInv] || 1) {
            // Compute sbox
            s = xInv ^ xInv << 1 ^ xInv << 2 ^ xInv << 3 ^ xInv << 4;
            s = s >> 8 ^ s & 255 ^ 99;
            sbox[x] = s;
            sboxInv[s] = x;
            // Compute MixColumns
            x8 = d[x4 = d[x2 = d[x]]];
            tDec = x8 * 0x1010101 ^ x4 * 0x10001 ^ x2 * 0x101 ^ x * 0x1010100;
            tEnc = d[s] * 0x101 ^ s * 0x1010100;
            for (i = 0; i < 4; i++) {
                encTable[i][x] = tEnc = tEnc << 24 ^ tEnc >>> 8;
                decTable[i][s] = tDec = tDec << 24 ^ tDec >>> 8;
            }
        }
        // Compactify.  Considerable speedup on Firefox.
        for (i = 0; i < 5; i++) {
            encTable[i] = encTable[i].slice(0);
            decTable[i] = decTable[i].slice(0);
        }
    },
    /**
     * Encryption and decryption core.
     * @param {Array} input Four words to be encrypted or decrypted.
     * @param dir The direction, 0 for encrypt and 1 for decrypt.
     * @return {Array} The four encrypted or decrypted words.
     * @private
     */
    _crypt: function (input, dir) {
        if (input.length !== 4) {
            throw new sjcl.exception.invalid("invalid aes block size");
        }
        var key = this._key[dir], 
        // state variables a,b,c,d are loaded with pre-whitened data
        a = input[0] ^ key[0], b = input[dir ? 3 : 1] ^ key[1], c = input[2] ^ key[2], d = input[dir ? 1 : 3] ^ key[3], a2, b2, c2, nInnerRounds = key.length / 4 - 2, i, kIndex = 4, out = [0, 0, 0, 0], table = this._tables[dir], 
        // load up the tables
        t0 = table[0], t1 = table[1], t2 = table[2], t3 = table[3], sbox = table[4];
        // Inner rounds.  Cribbed from OpenSSL.
        for (i = 0; i < nInnerRounds; i++) {
            a2 = t0[a >>> 24] ^ t1[b >> 16 & 255] ^ t2[c >> 8 & 255] ^ t3[d & 255] ^ key[kIndex];
            b2 = t0[b >>> 24] ^ t1[c >> 16 & 255] ^ t2[d >> 8 & 255] ^ t3[a & 255] ^ key[kIndex + 1];
            c2 = t0[c >>> 24] ^ t1[d >> 16 & 255] ^ t2[a >> 8 & 255] ^ t3[b & 255] ^ key[kIndex + 2];
            d = t0[d >>> 24] ^ t1[a >> 16 & 255] ^ t2[b >> 8 & 255] ^ t3[c & 255] ^ key[kIndex + 3];
            kIndex += 4;
            a = a2;
            b = b2;
            c = c2;
        }
        // Last round.
        for (i = 0; i < 4; i++) {
            out[dir ? 3 & -i : i] =
                sbox[a >>> 24] << 24 ^
                    sbox[b >> 16 & 255] << 16 ^
                    sbox[c >> 8 & 255] << 8 ^
                    sbox[d & 255] ^
                    key[kIndex++];
            a2 = a;
            a = b;
            b = c;
            c = d;
            d = a2;
        }
        return out;
    }
};
/** @fileOverview Arrays of bits, encoded as arrays of Numbers.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/**
 * Arrays of bits, encoded as arrays of Numbers.
 * @namespace
 * @description
 * <p>
 * These objects are the currency accepted by SJCL's crypto functions.
 * </p>
 *
 * <p>
 * Most of our crypto primitives operate on arrays of 4-byte words internally,
 * but many of them can take arguments that are not a multiple of 4 bytes.
 * This library encodes arrays of bits (whose size need not be a multiple of 8
 * bits) as arrays of 32-bit words.  The bits are packed, big-endian, into an
 * array of words, 32 bits at a time.  Since the words are double-precision
 * floating point numbers, they fit some extra data.  We use this (in a private,
 * possibly-changing manner) to encode the number of bits actually  present
 * in the last word of the array.
 * </p>
 *
 * <p>
 * Because bitwise ops clear this out-of-band data, these arrays can be passed
 * to ciphers like AES which want arrays of words.
 * </p>
 */
sjcl.bitArray = {
    /**
     * Array slices in units of bits.
     * @param {bitArray} a The array to slice.
     * @param {Number} bstart The offset to the start of the slice, in bits.
     * @param {Number} bend The offset to the end of the slice, in bits.  If this is undefined,
     * slice until the end of the array.
     * @return {bitArray} The requested slice.
     */
    bitSlice: function (a, bstart, bend) {
        a = sjcl.bitArray._shiftRight(a.slice(bstart / 32), 32 - (bstart & 31)).slice(1);
        return (bend === undefined) ? a : sjcl.bitArray.clamp(a, bend - bstart);
    },
    /**
     * Extract a number packed into a bit array.
     * @param {bitArray} a The array to slice.
     * @param {Number} bstart The offset to the start of the slice, in bits.
     * @param {Number} blength The length of the number to extract.
     * @return {Number} The requested slice.
     */
    extract: function (a, bstart, blength) {
        // FIXME: this Math.floor is not necessary at all, but for some reason
        // seems to suppress a bug in the Chromium JIT.
        var x, sh = Math.floor((-bstart - blength) & 31);
        if ((bstart + blength - 1 ^ bstart) & -32) {
            // it crosses a boundary
            x = (a[bstart / 32 | 0] << (32 - sh)) ^ (a[bstart / 32 + 1 | 0] >>> sh);
        }
        else {
            // within a single word
            x = a[bstart / 32 | 0] >>> sh;
        }
        return x & ((1 << blength) - 1);
    },
    /**
     * Concatenate two bit arrays.
     * @param {bitArray} a1 The first array.
     * @param {bitArray} a2 The second array.
     * @return {bitArray} The concatenation of a1 and a2.
     */
    concat: function (a1, a2) {
        if (a1.length === 0 || a2.length === 0) {
            return a1.concat(a2);
        }
        var last = a1[a1.length - 1], shift = sjcl.bitArray.getPartial(last);
        if (shift === 32) {
            return a1.concat(a2);
        }
        else {
            return sjcl.bitArray._shiftRight(a2, shift, last | 0, a1.slice(0, a1.length - 1));
        }
    },
    /**
     * Find the length of an array of bits.
     * @param {bitArray} a The array.
     * @return {Number} The length of a, in bits.
     */
    bitLength: function (a) {
        var l = a.length, x;
        if (l === 0) {
            return 0;
        }
        x = a[l - 1];
        return (l - 1) * 32 + sjcl.bitArray.getPartial(x);
    },
    /**
     * Truncate an array.
     * @param {bitArray} a The array.
     * @param {Number} len The length to truncate to, in bits.
     * @return {bitArray} A new array, truncated to len bits.
     */
    clamp: function (a, len) {
        if (a.length * 32 < len) {
            return a;
        }
        a = a.slice(0, Math.ceil(len / 32));
        var l = a.length;
        len = len & 31;
        if (l > 0 && len) {
            a[l - 1] = sjcl.bitArray.partial(len, a[l - 1] & 0x80000000 >> (len - 1), 1);
        }
        return a;
    },
    /**
     * Make a partial word for a bit array.
     * @param {Number} len The number of bits in the word.
     * @param {Number} x The bits.
     * @param {Number} [_end=0] Pass 1 if x has already been shifted to the high side.
     * @return {Number} The partial word.
     */
    partial: function (len, x, _end) {
        if (len === 32) {
            return x;
        }
        return (_end ? x | 0 : x << (32 - len)) + len * 0x10000000000;
    },
    /**
     * Get the number of bits used by a partial word.
     * @param {Number} x The partial word.
     * @return {Number} The number of bits used by the partial word.
     */
    getPartial: function (x) {
        return Math.round(x / 0x10000000000) || 32;
    },
    /**
     * Compare two arrays for equality in a predictable amount of time.
     * @param {bitArray} a The first array.
     * @param {bitArray} b The second array.
     * @return {boolean} true if a == b; false otherwise.
     */
    equal: function (a, b) {
        if (sjcl.bitArray.bitLength(a) !== sjcl.bitArray.bitLength(b)) {
            return false;
        }
        var x = 0, i;
        for (i = 0; i < a.length; i++) {
            x |= a[i] ^ b[i];
        }
        return (x === 0);
    },
    /** Shift an array right.
     * @param {bitArray} a The array to shift.
     * @param {Number} shift The number of bits to shift.
     * @param {Number} [carry=0] A byte to carry in
     * @param {bitArray} [out=[]] An array to prepend to the output.
     * @private
     */
    _shiftRight: function (a, shift, carry, out) {
        var i, last2 = 0, shift2;
        if (out === undefined) {
            out = [];
        }
        for (; shift >= 32; shift -= 32) {
            out.push(carry);
            carry = 0;
        }
        if (shift === 0) {
            return out.concat(a);
        }
        for (i = 0; i < a.length; i++) {
            out.push(carry | a[i] >>> shift);
            carry = a[i] << (32 - shift);
        }
        last2 = a.length ? a[a.length - 1] : 0;
        shift2 = sjcl.bitArray.getPartial(last2);
        out.push(sjcl.bitArray.partial(shift + shift2 & 31, (shift + shift2 > 32) ? carry : out.pop(), 1));
        return out;
    },
    /** xor a block of 4 words together.
     * @private
     */
    _xor4: function (x, y) {
        return [x[0] ^ y[0], x[1] ^ y[1], x[2] ^ y[2], x[3] ^ y[3]];
    },
    /** byteswap a word array inplace.
     * (does not handle partial words)
     * @param {sjcl.bitArray} a word array
     * @return {sjcl.bitArray} byteswapped array
     */
    byteswapM: function (a) {
        var i, v, m = 0xff00;
        for (i = 0; i < a.length; ++i) {
            v = a[i];
            a[i] = (v >>> 24) | ((v >>> 8) & m) | ((v & m) << 8) | (v << 24);
        }
        return a;
    }
};
/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/**
 * UTF-8 strings
 * @namespace
 */
sjcl.codec.utf8String = {
    /** Convert from a bitArray to a UTF-8 string. */
    fromBits: function (arr) {
        var out = "", bl = sjcl.bitArray.bitLength(arr), i, tmp;
        for (i = 0; i < bl / 8; i++) {
            if ((i & 3) === 0) {
                tmp = arr[i / 4];
            }
            out += String.fromCharCode(tmp >>> 8 >>> 8 >>> 8);
            tmp <<= 8;
        }
        return decodeURIComponent(escape(out));
    },
    /** Convert from a UTF-8 string to a bitArray. */
    toBits: function (str) {
        str = unescape(encodeURIComponent(str));
        var out = [], i, tmp = 0;
        for (i = 0; i < str.length; i++) {
            tmp = tmp << 8 | str.charCodeAt(i);
            if ((i & 3) === 3) {
                out.push(tmp);
                tmp = 0;
            }
        }
        if (i & 3) {
            out.push(sjcl.bitArray.partial(8 * (i & 3), tmp));
        }
        return out;
    }
};
/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/**
 * Hexadecimal
 * @namespace
 */
sjcl.codec.hex = {
    /** Convert from a bitArray to a hex string. */
    fromBits: function (arr) {
        var out = "", i;
        for (i = 0; i < arr.length; i++) {
            out += ((arr[i] | 0) + 0xF00000000000).toString(16).substr(4);
        }
        return out.substr(0, sjcl.bitArray.bitLength(arr) / 4); //.replace(/(.{8})/g, "$1 ");
    },
    /** Convert from a hex string to a bitArray. */
    toBits: function (str) {
        var i, out = [], len;
        str = str.replace(/\s|0x/g, "");
        len = str.length;
        str = str + "00000000";
        for (i = 0; i < str.length; i += 8) {
            out.push(parseInt(str.substr(i, 8), 16) ^ 0);
        }
        return sjcl.bitArray.clamp(out, len * 4);
    }
};
/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/**
 * Base64 encoding/decoding
 * @namespace
 */
sjcl.codec.base64 = {
    /** The base64 alphabet.
     * @private
     */
    _chars: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    /** Convert from a bitArray to a base64 string. */
    fromBits: function (arr, _noEquals, _url) {
        var out = "", i, bits = 0, c = sjcl.codec.base64._chars, ta = 0, bl = sjcl.bitArray.bitLength(arr);
        if (_url) {
            c = c.substr(0, 62) + '-_';
        }
        for (i = 0; out.length * 6 < bl;) {
            out += c.charAt((ta ^ arr[i] >>> bits) >>> 26);
            if (bits < 6) {
                ta = arr[i] << (6 - bits);
                bits += 26;
                i++;
            }
            else {
                ta <<= 6;
                bits -= 6;
            }
        }
        while ((out.length & 3) && !_noEquals) {
            out += "=";
        }
        return out;
    },
    /** Convert from a base64 string to a bitArray */
    toBits: function (str, _url) {
        str = str.replace(/\s|=/g, '');
        var out = [], i, bits = 0, c = sjcl.codec.base64._chars, ta = 0, x;
        if (_url) {
            c = c.substr(0, 62) + '-_';
        }
        for (i = 0; i < str.length; i++) {
            x = c.indexOf(str.charAt(i));
            if (x < 0) {
                throw new sjcl.exception.invalid("this isn't base64!");
            }
            if (bits > 26) {
                bits -= 26;
                out.push(ta ^ x >>> bits);
                ta = x << (32 - bits);
            }
            else {
                bits += 6;
                ta ^= x << (32 - bits);
            }
        }
        if (bits & 56) {
            out.push(sjcl.bitArray.partial(bits & 56, ta, 1));
        }
        return out;
    }
};
sjcl.codec.base64url = {
    fromBits: function (arr) { return sjcl.codec.base64.fromBits(arr, 1, 1); },
    toBits: function (str) { return sjcl.codec.base64.toBits(str, 1); }
};
/** @fileOverview Bit array codec implementations.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/**
 * Arrays of bytes
 * @namespace
 */
sjcl.codec.bytes = {
    /** Convert from a bitArray to an array of bytes. */
    fromBits: function (arr) {
        var out = [], bl = sjcl.bitArray.bitLength(arr), i, tmp;
        for (i = 0; i < bl / 8; i++) {
            if ((i & 3) === 0) {
                tmp = arr[i / 4];
            }
            out.push(tmp >>> 24);
            tmp <<= 8;
        }
        return out;
    },
    /** Convert from an array of bytes to a bitArray. */
    toBits: function (bytes) {
        var out = [], i, tmp = 0;
        for (i = 0; i < bytes.length; i++) {
            tmp = tmp << 8 | bytes[i];
            if ((i & 3) === 3) {
                out.push(tmp);
                tmp = 0;
            }
        }
        if (i & 3) {
            out.push(sjcl.bitArray.partial(8 * (i & 3), tmp));
        }
        return out;
    }
};
/** @fileOverview Javascript SHA-256 implementation.
 *
 * An older version of this implementation is available in the public
 * domain, but this one is (c) Emily Stark, Mike Hamburg, Dan Boneh,
 * Stanford University 2008-2010 and BSD-licensed for liability
 * reasons.
 *
 * Special thanks to Aldo Cortesi for pointing out several bugs in
 * this code.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/**
 * Context for a SHA-256 operation in progress.
 * @constructor
 */
sjcl.hash.sha256 = function (hash) {
    if (!this._key[0]) {
        this._precompute();
    }
    if (hash) {
        this._h = hash._h.slice(0);
        this._buffer = hash._buffer.slice(0);
        this._length = hash._length;
    }
    else {
        this.reset();
    }
};
/**
 * Hash a string or an array of words.
 * @static
 * @param {bitArray|String} data the data to hash.
 * @return {bitArray} The hash value, an array of 16 big-endian words.
 */
sjcl.hash.sha256.hash = function (data) {
    return (new sjcl.hash.sha256()).update(data).finalize();
};
sjcl.hash.sha256.prototype = {
    /**
     * The hash's block size, in bits.
     * @constant
     */
    blockSize: 512,
    /**
     * Reset the hash state.
     * @return this
     */
    reset: function () {
        this._h = this._init.slice(0);
        this._buffer = [];
        this._length = 0;
        return this;
    },
    /**
     * Input several words to the hash.
     * @param {bitArray|String} data the data to hash.
     * @return this
     */
    update: function (data) {
        if (typeof data === "string") {
            data = sjcl.codec.utf8String.toBits(data);
        }
        var i, b = this._buffer = sjcl.bitArray.concat(this._buffer, data), ol = this._length, nl = this._length = ol + sjcl.bitArray.bitLength(data);
        if (nl > 9007199254740991) {
            throw new sjcl.exception.invalid("Cannot hash more than 2^53 - 1 bits");
        }
        if (typeof Uint32Array !== 'undefined') {
            var c = new Uint32Array(b);
            var j = 0;
            for (i = 512 + ol - ((512 + ol) & 511); i <= nl; i += 512) {
                this._block(c.subarray(16 * j, 16 * (j + 1)));
                j += 1;
            }
            b.splice(0, 16 * j);
        }
        else {
            for (i = 512 + ol - ((512 + ol) & 511); i <= nl; i += 512) {
                this._block(b.splice(0, 16));
            }
        }
        return this;
    },
    /**
     * Complete hashing and output the hash value.
     * @return {bitArray} The hash value, an array of 8 big-endian words.
     */
    finalize: function () {
        var i, b = this._buffer, h = this._h;
        // Round out and push the buffer
        b = sjcl.bitArray.concat(b, [sjcl.bitArray.partial(1, 1)]);
        // Round out the buffer to a multiple of 16 words, less the 2 length words.
        for (i = b.length + 2; i & 15; i++) {
            b.push(0);
        }
        // append the length
        b.push(Math.floor(this._length / 0x100000000));
        b.push(this._length | 0);
        while (b.length) {
            this._block(b.splice(0, 16));
        }
        this.reset();
        return h;
    },
    /**
     * The SHA-256 initialization vector, to be precomputed.
     * @private
     */
    _init: [],
    /*
    _init:[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
    */
    /**
     * The SHA-256 hash key, to be precomputed.
     * @private
     */
    _key: [],
    /*
    _key:
      [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
       0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
       0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
       0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
       0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
       0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
       0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
       0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2],
    */
    /**
     * Function to precompute _init and _key.
     * @private
     */
    _precompute: function () {
        var i = 0, prime = 2, factor, isPrime;
        function frac(x) { return (x - Math.floor(x)) * 0x100000000 | 0; }
        for (; i < 64; prime++) {
            isPrime = true;
            for (factor = 2; factor * factor <= prime; factor++) {
                if (prime % factor === 0) {
                    isPrime = false;
                    break;
                }
            }
            if (isPrime) {
                if (i < 8) {
                    this._init[i] = frac(Math.pow(prime, 1 / 2));
                }
                this._key[i] = frac(Math.pow(prime, 1 / 3));
                i++;
            }
        }
    },
    /**
     * Perform one cycle of SHA-256.
     * @param {Uint32Array|bitArray} w one block of words.
     * @private
     */
    _block: function (w) {
        var i, tmp, a, b, h = this._h, k = this._key, h0 = h[0], h1 = h[1], h2 = h[2], h3 = h[3], h4 = h[4], h5 = h[5], h6 = h[6], h7 = h[7];
        /* Rationale for placement of |0 :
         * If a value can overflow is original 32 bits by a factor of more than a few
         * million (2^23 ish), there is a possibility that it might overflow the
         * 53-bit mantissa and lose precision.
         *
         * To avoid this, we clamp back to 32 bits by |'ing with 0 on any value that
         * propagates around the loop, and on the hash state h[].  I don't believe
         * that the clamps on h4 and on h0 are strictly necessary, but it's close
         * (for h4 anyway), and better safe than sorry.
         *
         * The clamps on h[] are necessary for the output to be correct even in the
         * common case and for short inputs.
         */
        for (i = 0; i < 64; i++) {
            // load up the input word for this round
            if (i < 16) {
                tmp = w[i];
            }
            else {
                a = w[(i + 1) & 15];
                b = w[(i + 14) & 15];
                tmp = w[i & 15] = ((a >>> 7 ^ a >>> 18 ^ a >>> 3 ^ a << 25 ^ a << 14) +
                    (b >>> 17 ^ b >>> 19 ^ b >>> 10 ^ b << 15 ^ b << 13) +
                    w[i & 15] + w[(i + 9) & 15]) | 0;
            }
            tmp = (tmp + h7 + (h4 >>> 6 ^ h4 >>> 11 ^ h4 >>> 25 ^ h4 << 26 ^ h4 << 21 ^ h4 << 7) + (h6 ^ h4 & (h5 ^ h6)) + k[i]); // | 0;
            // shift register
            h7 = h6;
            h6 = h5;
            h5 = h4;
            h4 = h3 + tmp | 0;
            h3 = h2;
            h2 = h1;
            h1 = h0;
            h0 = (tmp + ((h1 & h2) ^ (h3 & (h1 ^ h2))) + (h1 >>> 2 ^ h1 >>> 13 ^ h1 >>> 22 ^ h1 << 30 ^ h1 << 19 ^ h1 << 10)) | 0;
        }
        h[0] = h[0] + h0 | 0;
        h[1] = h[1] + h1 | 0;
        h[2] = h[2] + h2 | 0;
        h[3] = h[3] + h3 | 0;
        h[4] = h[4] + h4 | 0;
        h[5] = h[5] + h5 | 0;
        h[6] = h[6] + h6 | 0;
        h[7] = h[7] + h7 | 0;
    }
};
/** @fileOverview CCM mode implementation.
 *
 * Special thanks to Roy Nicholson for pointing out a bug in our
 * implementation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/**
 * CTR mode with CBC MAC.
 * @namespace
 */
sjcl.mode.ccm = {
    /** The name of the mode.
     * @constant
     */
    name: "ccm",
    _progressListeners: [],
    listenProgress: function (cb) {
        sjcl.mode.ccm._progressListeners.push(cb);
    },
    unListenProgress: function (cb) {
        var index = sjcl.mode.ccm._progressListeners.indexOf(cb);
        if (index > -1) {
            sjcl.mode.ccm._progressListeners.splice(index, 1);
        }
    },
    _callProgressListener: function (val) {
        var p = sjcl.mode.ccm._progressListeners.slice(), i;
        for (i = 0; i < p.length; i += 1) {
            p[i](val);
        }
    },
    /** Encrypt in CCM mode.
     * @static
     * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
     * @param {bitArray} plaintext The plaintext data.
     * @param {bitArray} iv The initialization value.
     * @param {bitArray} [adata=[]] The authenticated data.
     * @param {Number} [tlen=64] the desired tag length, in bits.
     * @return {bitArray} The encrypted data, an array of bytes.
     */
    encrypt: function (prf, plaintext, iv, adata, tlen) {
        var L, out = plaintext.slice(0), tag, w = sjcl.bitArray, ivl = w.bitLength(iv) / 8, ol = w.bitLength(out) / 8;
        tlen = tlen || 64;
        adata = adata || [];
        if (ivl < 7) {
            throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");
        }
        // compute the length of the length
        for (L = 2; L < 4 && ol >>> 8 * L; L++) { }
        if (L < 15 - ivl) {
            L = 15 - ivl;
        }
        iv = w.clamp(iv, 8 * (15 - L));
        // compute the tag
        tag = sjcl.mode.ccm._computeTag(prf, plaintext, iv, adata, tlen, L);
        // encrypt
        out = sjcl.mode.ccm._ctrMode(prf, out, iv, tag, tlen, L);
        return w.concat(out.data, out.tag);
    },
    /** Decrypt in CCM mode.
     * @static
     * @param {Object} prf The pseudorandom function.  It must have a block size of 16 bytes.
     * @param {bitArray} ciphertext The ciphertext data.
     * @param {bitArray} iv The initialization value.
     * @param {bitArray} [adata=[]] adata The authenticated data.
     * @param {Number} [tlen=64] tlen the desired tag length, in bits.
     * @return {bitArray} The decrypted data.
     */
    decrypt: function (prf, ciphertext, iv, adata, tlen) {
        tlen = tlen || 64;
        adata = adata || [];
        var L, w = sjcl.bitArray, ivl = w.bitLength(iv) / 8, ol = w.bitLength(ciphertext), out = w.clamp(ciphertext, ol - tlen), tag = w.bitSlice(ciphertext, ol - tlen), tag2;
        ol = (ol - tlen) / 8;
        if (ivl < 7) {
            throw new sjcl.exception.invalid("ccm: iv must be at least 7 bytes");
        }
        // compute the length of the length
        for (L = 2; L < 4 && ol >>> 8 * L; L++) { }
        if (L < 15 - ivl) {
            L = 15 - ivl;
        }
        iv = w.clamp(iv, 8 * (15 - L));
        // decrypt
        out = sjcl.mode.ccm._ctrMode(prf, out, iv, tag, tlen, L);
        // check the tag
        tag2 = sjcl.mode.ccm._computeTag(prf, out.data, iv, adata, tlen, L);
        if (!w.equal(out.tag, tag2)) {
            throw new sjcl.exception.corrupt("ccm: tag doesn't match");
        }
        return out.data;
    },
    _macAdditionalData: function (prf, adata, iv, tlen, ol, L) {
        var mac, tmp, i, macData = [], w = sjcl.bitArray, xor = w._xor4;
        // mac the flags
        mac = [w.partial(8, (adata.length ? 1 << 6 : 0) | (tlen - 2) << 2 | L - 1)];
        // mac the iv and length
        mac = w.concat(mac, iv);
        mac[3] |= ol;
        mac = prf.encrypt(mac);
        if (adata.length) {
            // mac the associated data.  start with its length...
            tmp = w.bitLength(adata) / 8;
            if (tmp <= 0xFEFF) {
                macData = [w.partial(16, tmp)];
            }
            else if (tmp <= 0xFFFFFFFF) {
                macData = w.concat([w.partial(16, 0xFFFE)], [tmp]);
            } // else ...
            // mac the data itself
            macData = w.concat(macData, adata);
            for (i = 0; i < macData.length; i += 4) {
                mac = prf.encrypt(xor(mac, macData.slice(i, i + 4).concat([0, 0, 0])));
            }
        }
        return mac;
    },
    /* Compute the (unencrypted) authentication tag, according to the CCM specification
     * @param {Object} prf The pseudorandom function.
     * @param {bitArray} plaintext The plaintext data.
     * @param {bitArray} iv The initialization value.
     * @param {bitArray} adata The authenticated data.
     * @param {Number} tlen the desired tag length, in bits.
     * @return {bitArray} The tag, but not yet encrypted.
     * @private
     */
    _computeTag: function (prf, plaintext, iv, adata, tlen, L) {
        // compute B[0]
        var mac, i, w = sjcl.bitArray, xor = w._xor4;
        tlen /= 8;
        // check tag length and message length
        if (tlen % 2 || tlen < 4 || tlen > 16) {
            throw new sjcl.exception.invalid("ccm: invalid tag length");
        }
        if (adata.length > 0xFFFFFFFF || plaintext.length > 0xFFFFFFFF) {
            // I don't want to deal with extracting high words from doubles.
            throw new sjcl.exception.bug("ccm: can't deal with 4GiB or more data");
        }
        mac = sjcl.mode.ccm._macAdditionalData(prf, adata, iv, tlen, w.bitLength(plaintext) / 8, L);
        // mac the plaintext
        for (i = 0; i < plaintext.length; i += 4) {
            mac = prf.encrypt(xor(mac, plaintext.slice(i, i + 4).concat([0, 0, 0])));
        }
        return w.clamp(mac, tlen * 8);
    },
    /** CCM CTR mode.
     * Encrypt or decrypt data and tag with the prf in CCM-style CTR mode.
     * May mutate its arguments.
     * @param {Object} prf The PRF.
     * @param {bitArray} data The data to be encrypted or decrypted.
     * @param {bitArray} iv The initialization vector.
     * @param {bitArray} tag The authentication tag.
     * @param {Number} tlen The length of th etag, in bits.
     * @param {Number} L The CCM L value.
     * @return {Object} An object with data and tag, the en/decryption of data and tag values.
     * @private
     */
    _ctrMode: function (prf, data, iv, tag, tlen, L) {
        var enc, i, w = sjcl.bitArray, xor = w._xor4, ctr, l = data.length, bl = w.bitLength(data), n = l / 50, p = n;
        // start the ctr
        ctr = w.concat([w.partial(8, L - 1)], iv).concat([0, 0, 0]).slice(0, 4);
        // en/decrypt the tag
        tag = w.bitSlice(xor(tag, prf.encrypt(ctr)), 0, tlen);
        // en/decrypt the data
        if (!l) {
            return { tag: tag, data: [] };
        }
        for (i = 0; i < l; i += 4) {
            if (i > n) {
                sjcl.mode.ccm._callProgressListener(i / l);
                n += p;
            }
            ctr[3]++;
            enc = prf.encrypt(ctr);
            data[i] ^= enc[0];
            data[i + 1] ^= enc[1];
            data[i + 2] ^= enc[2];
            data[i + 3] ^= enc[3];
        }
        return { tag: tag, data: w.clamp(data, bl) };
    }
};
/** @fileOverview HMAC implementation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/** HMAC with the specified hash function.
 * @constructor
 * @param {bitArray} key the key for HMAC.
 * @param {Object} [Hash=sjcl.hash.sha256] The hash function to use.
 */
sjcl.misc.hmac = function (key, Hash) {
    this._hash = Hash = Hash || sjcl.hash.sha256;
    var exKey = [[], []], i, bs = Hash.prototype.blockSize / 32;
    this._baseHash = [new Hash(), new Hash()];
    if (key.length > bs) {
        key = Hash.hash(key);
    }
    for (i = 0; i < bs; i++) {
        exKey[0][i] = key[i] ^ 0x36363636;
        exKey[1][i] = key[i] ^ 0x5C5C5C5C;
    }
    this._baseHash[0].update(exKey[0]);
    this._baseHash[1].update(exKey[1]);
    this._resultHash = new Hash(this._baseHash[0]);
};
/** HMAC with the specified hash function.  Also called encrypt since it's a prf.
 * @param {bitArray|String} data The data to mac.
 */
sjcl.misc.hmac.prototype.encrypt = sjcl.misc.hmac.prototype.mac = function (data) {
    if (!this._updated) {
        this.update(data);
        return this.digest(data);
    }
    else {
        throw new sjcl.exception.invalid("encrypt on already updated hmac called!");
    }
};
sjcl.misc.hmac.prototype.reset = function () {
    this._resultHash = new this._hash(this._baseHash[0]);
    this._updated = false;
};
sjcl.misc.hmac.prototype.update = function (data) {
    this._updated = true;
    this._resultHash.update(data);
};
sjcl.misc.hmac.prototype.digest = function () {
    var w = this._resultHash.finalize(), result = new (this._hash)(this._baseHash[1]).update(w).finalize();
    this.reset();
    return result;
};
/** @fileOverview Password-based key-derivation function, version 2.0.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/** Password-Based Key-Derivation Function, version 2.0.
 *
 * Generate keys from passwords using PBKDF2-HMAC-SHA256.
 *
 * This is the method specified by RSA's PKCS #5 standard.
 *
 * @param {bitArray|String} password  The password.
 * @param {bitArray|String} salt The salt.  Should have lots of entropy.
 * @param {Number} [count=1000] The number of iterations.  Higher numbers make the function slower but more secure.
 * @param {Number} [length] The length of the derived key.  Defaults to the
                            output size of the hash function.
 * @param {Object} [Prff=sjcl.misc.hmac] The pseudorandom function family.
 * @return {bitArray} the derived key.
 */
sjcl.misc.pbkdf2 = function (password, salt, count, length, Prff) {
    count = count || 10000;
    if (length < 0 || count < 0) {
        throw new sjcl.exception.invalid("invalid params to pbkdf2");
    }
    if (typeof password === "string") {
        password = sjcl.codec.utf8String.toBits(password);
    }
    if (typeof salt === "string") {
        salt = sjcl.codec.utf8String.toBits(salt);
    }
    Prff = Prff || sjcl.misc.hmac;
    var prf = new Prff(password), u, ui, i, j, k, out = [], b = sjcl.bitArray;
    for (k = 1; 32 * out.length < (length || 1); k++) {
        u = ui = prf.encrypt(b.concat(salt, [k]));
        for (i = 1; i < count; i++) {
            ui = prf.encrypt(ui);
            for (j = 0; j < ui.length; j++) {
                u[j] ^= ui[j];
            }
        }
        out = out.concat(u);
    }
    if (length) {
        out = b.clamp(out, length);
    }
    return out;
};
/** @fileOverview Random number generator.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 * @author Michael Brooks
 * @author Steve Thomas
 */
/**
 * @class Random number generator
 * @description
 * <b>Use sjcl.random as a singleton for this class!</b>
 * <p>
 * This random number generator is a derivative of Ferguson and Schneier's
 * generator Fortuna.  It collects entropy from various events into several
 * pools, implemented by streaming SHA-256 instances.  It differs from
 * ordinary Fortuna in a few ways, though.
 * </p>
 *
 * <p>
 * Most importantly, it has an entropy estimator.  This is present because
 * there is a strong conflict here between making the generator available
 * as soon as possible, and making sure that it doesn't "run on empty".
 * In Fortuna, there is a saved state file, and the system is likely to have
 * time to warm up.
 * </p>
 *
 * <p>
 * Second, because users are unlikely to stay on the page for very long,
 * and to speed startup time, the number of pools increases logarithmically:
 * a new pool is created when the previous one is actually used for a reseed.
 * This gives the same asymptotic guarantees as Fortuna, but gives more
 * entropy to early reseeds.
 * </p>
 *
 * <p>
 * The entire mechanism here feels pretty klunky.  Furthermore, there are
 * several improvements that should be made, including support for
 * dedicated cryptographic functions that may be present in some browsers;
 * state files in local storage; cookies containing randomness; etc.  So
 * look for improvements in future versions.
 * </p>
 * @constructor
 */
sjcl.prng = function (defaultParanoia) {
    /* private */
    this._pools = [new sjcl.hash.sha256()];
    this._poolEntropy = [0];
    this._reseedCount = 0;
    this._robins = {};
    this._eventId = 0;
    this._collectorIds = {};
    this._collectorIdNext = 0;
    this._strength = 0;
    this._poolStrength = 0;
    this._nextReseed = 0;
    this._key = [0, 0, 0, 0, 0, 0, 0, 0];
    this._counter = [0, 0, 0, 0];
    this._cipher = undefined;
    this._defaultParanoia = defaultParanoia;
    /* event listener stuff */
    this._collectorsStarted = false;
    this._callbacks = { progress: {}, seeded: {} };
    this._callbackI = 0;
    /* constants */
    this._NOT_READY = 0;
    this._READY = 1;
    this._REQUIRES_RESEED = 2;
    this._MAX_WORDS_PER_BURST = 65536;
    this._PARANOIA_LEVELS = [0, 48, 64, 96, 128, 192, 256, 384, 512, 768, 1024];
    this._MILLISECONDS_PER_RESEED = 30000;
    this._BITS_PER_RESEED = 80;
};
sjcl.prng.prototype = {
    /** Generate several random words, and return them in an array.
     * A word consists of 32 bits (4 bytes)
     * @param {Number} nwords The number of words to generate.
     */
    randomWords: function (nwords, paranoia) {
        var out = [], i, readiness = this.isReady(paranoia), g;
        if (readiness === this._NOT_READY) {
            throw new sjcl.exception.notReady("generator isn't seeded");
        }
        else if (readiness & this._REQUIRES_RESEED) {
            this._reseedFromPools(!(readiness & this._READY));
        }
        for (i = 0; i < nwords; i += 4) {
            if ((i + 1) % this._MAX_WORDS_PER_BURST === 0) {
                this._gate();
            }
            g = this._gen4words();
            out.push(g[0], g[1], g[2], g[3]);
        }
        this._gate();
        return out.slice(0, nwords);
    },
    setDefaultParanoia: function (paranoia, allowZeroParanoia) {
        if (paranoia === 0 && allowZeroParanoia !== "Setting paranoia=0 will ruin your security; use it only for testing") {
            throw new sjcl.exception.invalid("Setting paranoia=0 will ruin your security; use it only for testing");
        }
        this._defaultParanoia = paranoia;
    },
    /**
     * Add entropy to the pools.
     * @param data The entropic value.  Should be a 32-bit integer, array of 32-bit integers, or string
     * @param {Number} estimatedEntropy The estimated entropy of data, in bits
     * @param {String} source The source of the entropy, eg "mouse"
     */
    addEntropy: function (data, estimatedEntropy, source) {
        source = source || "user";
        var id, i, tmp, t = (new Date()).valueOf(), robin = this._robins[source], oldReady = this.isReady(), err = 0, objName;
        id = this._collectorIds[source];
        if (id === undefined) {
            id = this._collectorIds[source] = this._collectorIdNext++;
        }
        if (robin === undefined) {
            robin = this._robins[source] = 0;
        }
        this._robins[source] = (this._robins[source] + 1) % this._pools.length;
        switch (typeof (data)) {
            case "number":
                if (estimatedEntropy === undefined) {
                    estimatedEntropy = 1;
                }
                this._pools[robin].update([id, this._eventId++, 1, estimatedEntropy, t, 1, data | 0]);
                break;
            case "object":
                objName = Object.prototype.toString.call(data);
                if (objName === "[object Uint32Array]") {
                    tmp = [];
                    for (i = 0; i < data.length; i++) {
                        tmp.push(data[i]);
                    }
                    data = tmp;
                }
                else {
                    if (objName !== "[object Array]") {
                        err = 1;
                    }
                    for (i = 0; i < data.length && !err; i++) {
                        if (typeof (data[i]) !== "number") {
                            err = 1;
                        }
                    }
                }
                if (!err) {
                    if (estimatedEntropy === undefined) {
                        /* horrible entropy estimator */
                        estimatedEntropy = 0;
                        for (i = 0; i < data.length; i++) {
                            tmp = data[i];
                            while (tmp > 0) {
                                estimatedEntropy++;
                                tmp = tmp >>> 1;
                            }
                        }
                    }
                    this._pools[robin].update([id, this._eventId++, 2, estimatedEntropy, t, data.length].concat(data));
                }
                break;
            case "string":
                if (estimatedEntropy === undefined) {
                    /* English text has just over 1 bit per character of entropy.
                     * But this might be HTML or something, and have far less
                     * entropy than English...  Oh well, let's just say one bit.
                     */
                    estimatedEntropy = data.length;
                }
                this._pools[robin].update([id, this._eventId++, 3, estimatedEntropy, t, data.length]);
                this._pools[robin].update(data);
                break;
            default:
                err = 1;
        }
        if (err) {
            throw new sjcl.exception.bug("random: addEntropy only supports number, array of numbers or string");
        }
        /* record the new strength */
        this._poolEntropy[robin] += estimatedEntropy;
        this._poolStrength += estimatedEntropy;
        /* fire off events */
        if (oldReady === this._NOT_READY) {
            if (this.isReady() !== this._NOT_READY) {
                this._fireEvent("seeded", Math.max(this._strength, this._poolStrength));
            }
            this._fireEvent("progress", this.getProgress());
        }
    },
    /** Is the generator ready? */
    isReady: function (paranoia) {
        var entropyRequired = this._PARANOIA_LEVELS[(paranoia !== undefined) ? paranoia : this._defaultParanoia];
        if (this._strength && this._strength >= entropyRequired) {
            return (this._poolEntropy[0] > this._BITS_PER_RESEED && (new Date()).valueOf() > this._nextReseed) ?
                this._REQUIRES_RESEED | this._READY :
                this._READY;
        }
        else {
            return (this._poolStrength >= entropyRequired) ?
                this._REQUIRES_RESEED | this._NOT_READY :
                this._NOT_READY;
        }
    },
    /** Get the generator's progress toward readiness, as a fraction */
    getProgress: function (paranoia) {
        var entropyRequired = this._PARANOIA_LEVELS[paranoia ? paranoia : this._defaultParanoia];
        if (this._strength >= entropyRequired) {
            return 1.0;
        }
        else {
            return (this._poolStrength > entropyRequired) ?
                1.0 :
                this._poolStrength / entropyRequired;
        }
    },
    /** start the built-in entropy collectors */
    startCollectors: function () {
        if (this._collectorsStarted) {
            return;
        }
        this._eventListener = {
            loadTimeCollector: this._bind(this._loadTimeCollector),
            mouseCollector: this._bind(this._mouseCollector),
            keyboardCollector: this._bind(this._keyboardCollector),
            accelerometerCollector: this._bind(this._accelerometerCollector),
            touchCollector: this._bind(this._touchCollector)
        };
        if (window.addEventListener) {
            window.addEventListener("load", this._eventListener.loadTimeCollector, false);
            window.addEventListener("mousemove", this._eventListener.mouseCollector, false);
            window.addEventListener("keypress", this._eventListener.keyboardCollector, false);
            window.addEventListener("devicemotion", this._eventListener.accelerometerCollector, false);
            window.addEventListener("touchmove", this._eventListener.touchCollector, false);
        }
        else if (document.attachEvent) {
            document.attachEvent("onload", this._eventListener.loadTimeCollector);
            document.attachEvent("onmousemove", this._eventListener.mouseCollector);
            document.attachEvent("keypress", this._eventListener.keyboardCollector);
        }
        else {
            throw new sjcl.exception.bug("can't attach event");
        }
        this._collectorsStarted = true;
    },
    /** stop the built-in entropy collectors */
    stopCollectors: function () {
        if (!this._collectorsStarted) {
            return;
        }
        if (window.removeEventListener) {
            window.removeEventListener("load", this._eventListener.loadTimeCollector, false);
            window.removeEventListener("mousemove", this._eventListener.mouseCollector, false);
            window.removeEventListener("keypress", this._eventListener.keyboardCollector, false);
            window.removeEventListener("devicemotion", this._eventListener.accelerometerCollector, false);
            window.removeEventListener("touchmove", this._eventListener.touchCollector, false);
        }
        else if (document.detachEvent) {
            document.detachEvent("onload", this._eventListener.loadTimeCollector);
            document.detachEvent("onmousemove", this._eventListener.mouseCollector);
            document.detachEvent("keypress", this._eventListener.keyboardCollector);
        }
        this._collectorsStarted = false;
    },
    /* use a cookie to store entropy.
    useCookie: function (all_cookies) {
        throw new sjcl.exception.bug("random: useCookie is unimplemented");
    },*/
    /** add an event listener for progress or seeded-ness. */
    addEventListener: function (name, callback) {
        this._callbacks[name][this._callbackI++] = callback;
    },
    /** remove an event listener for progress or seeded-ness */
    removeEventListener: function (name, cb) {
        var i, j, cbs = this._callbacks[name], jsTemp = [];
        /* I'm not sure if this is necessary; in C++, iterating over a
         * collection and modifying it at the same time is a no-no.
         */
        for (j in cbs) {
            if (cbs.hasOwnProperty(j) && cbs[j] === cb) {
                jsTemp.push(j);
            }
        }
        for (i = 0; i < jsTemp.length; i++) {
            j = jsTemp[i];
            delete cbs[j];
        }
    },
    _bind: function (func) {
        var that = this;
        return function () {
            func.apply(that, arguments);
        };
    },
    /** Generate 4 random words, no reseed, no gate.
     * @private
     */
    _gen4words: function () {
        for (var i = 0; i < 4; i++) {
            this._counter[i] = this._counter[i] + 1 | 0;
            if (this._counter[i]) {
                break;
            }
        }
        return this._cipher.encrypt(this._counter);
    },
    /* Rekey the AES instance with itself after a request, or every _MAX_WORDS_PER_BURST words.
     * @private
     */
    _gate: function () {
        this._key = this._gen4words().concat(this._gen4words());
        this._cipher = new sjcl.cipher.aes(this._key);
    },
    /** Reseed the generator with the given words
     * @private
     */
    _reseed: function (seedWords) {
        this._key = sjcl.hash.sha256.hash(this._key.concat(seedWords));
        this._cipher = new sjcl.cipher.aes(this._key);
        for (var i = 0; i < 4; i++) {
            this._counter[i] = this._counter[i] + 1 | 0;
            if (this._counter[i]) {
                break;
            }
        }
    },
    /** reseed the data from the entropy pools
     * @param full If set, use all the entropy pools in the reseed.
     */
    _reseedFromPools: function (full) {
        var reseedData = [], strength = 0, i;
        this._nextReseed = reseedData[0] =
            (new Date()).valueOf() + this._MILLISECONDS_PER_RESEED;
        for (i = 0; i < 16; i++) {
            /* On some browsers, this is cryptographically random.  So we might
             * as well toss it in the pot and stir...
             */
            reseedData.push(Math.random() * 0x100000000 | 0);
        }
        for (i = 0; i < this._pools.length; i++) {
            reseedData = reseedData.concat(this._pools[i].finalize());
            strength += this._poolEntropy[i];
            this._poolEntropy[i] = 0;
            if (!full && (this._reseedCount & (1 << i))) {
                break;
            }
        }
        /* if we used the last pool, push a new one onto the stack */
        if (this._reseedCount >= 1 << this._pools.length) {
            this._pools.push(new sjcl.hash.sha256());
            this._poolEntropy.push(0);
        }
        /* how strong was this reseed? */
        this._poolStrength -= strength;
        if (strength > this._strength) {
            this._strength = strength;
        }
        this._reseedCount++;
        this._reseed(reseedData);
    },
    _keyboardCollector: function () {
        this._addCurrentTimeToEntropy(1);
    },
    _mouseCollector: function (ev) {
        var x, y;
        try {
            x = ev.x || ev.clientX || ev.offsetX || 0;
            y = ev.y || ev.clientY || ev.offsetY || 0;
        }
        catch (err) {
            // Event originated from a secure element. No mouse position available.
            x = 0;
            y = 0;
        }
        if (x != 0 && y != 0) {
            this.addEntropy([x, y], 2, "mouse");
        }
        this._addCurrentTimeToEntropy(0);
    },
    _touchCollector: function (ev) {
        var touch = ev.touches[0] || ev.changedTouches[0];
        var x = touch.pageX || touch.clientX, y = touch.pageY || touch.clientY;
        this.addEntropy([x, y], 1, "touch");
        this._addCurrentTimeToEntropy(0);
    },
    _loadTimeCollector: function () {
        this._addCurrentTimeToEntropy(2);
    },
    _addCurrentTimeToEntropy: function (estimatedEntropy) {
        if (typeof window !== 'undefined' && window.performance && typeof window.performance.now === "function") {
            //how much entropy do we want to add here?
            this.addEntropy(window.performance.now(), estimatedEntropy, "loadtime");
        }
        else {
            this.addEntropy((new Date()).valueOf(), estimatedEntropy, "loadtime");
        }
    },
    _accelerometerCollector: function (ev) {
        var ac = ev.accelerationIncludingGravity.x || ev.accelerationIncludingGravity.y || ev.accelerationIncludingGravity.z;
        if (window.orientation) {
            var or = window.orientation;
            if (typeof or === "number") {
                this.addEntropy(or, 1, "accelerometer");
            }
        }
        if (ac) {
            this.addEntropy(ac, 2, "accelerometer");
        }
        this._addCurrentTimeToEntropy(0);
    },
    _fireEvent: function (name, arg) {
        var j, cbs = sjcl.random._callbacks[name], cbsTemp = [];
        /* TODO: there is a race condition between removing collectors and firing them */
        /* I'm not sure if this is necessary; in C++, iterating over a
         * collection and modifying it at the same time is a no-no.
         */
        for (j in cbs) {
            if (cbs.hasOwnProperty(j)) {
                cbsTemp.push(cbs[j]);
            }
        }
        for (j = 0; j < cbsTemp.length; j++) {
            cbsTemp[j](arg);
        }
    }
};
/** an instance for the prng.
* @see sjcl.prng
*/
sjcl.random = new sjcl.prng(6);
(function () {
    // function for getting nodejs crypto module. catches and ignores errors.
    function getCryptoModule() {
        try {
            return require('crypto');
        }
        catch (e) {
            return null;
        }
    }
    try {
        var buf, crypt, ab;
        // get cryptographically strong entropy depending on runtime environment
        if (typeof module !== 'undefined' && module.exports && (crypt = getCryptoModule()) && crypt.randomBytes) {
            buf = crypt.randomBytes(1024 / 8);
            buf = new Uint32Array(new Uint8Array(buf).buffer);
            sjcl.random.addEntropy(buf, 1024, "crypto.randomBytes");
        }
        else if (typeof window !== 'undefined' && typeof Uint32Array !== 'undefined') {
            ab = new Uint32Array(32);
            if (window.crypto && window.crypto.getRandomValues) {
                window.crypto.getRandomValues(ab);
            }
            else if (window.msCrypto && window.msCrypto.getRandomValues) {
                window.msCrypto.getRandomValues(ab);
            }
            else {
                return;
            }
            // get cryptographically strong entropy in Webkit
            sjcl.random.addEntropy(ab, 1024, "crypto.getRandomValues");
        }
        else {
            // no getRandomValues :-(
        }
    }
    catch (e) {
        if (typeof window !== 'undefined' && window.console) {
            console.log("There was an error collecting entropy from the browser:");
            console.log(e);
            //we do not want the library to fail due to randomness not being maintained.
        }
    }
}());
/** @fileOverview Convenience functions centered around JSON encapsulation.
 *
 * @author Emily Stark
 * @author Mike Hamburg
 * @author Dan Boneh
 */
/**
 * JSON encapsulation
 * @namespace
 */
sjcl.json = {
    /** Default values for encryption */
    defaults: { v: 1, iter: 10000, ks: 128, ts: 64, mode: "ccm", adata: "", cipher: "aes" },
    /** Simple encryption function.
     * @param {String|bitArray} password The password or key.
     * @param {String} plaintext The data to encrypt.
     * @param {Object} [params] The parameters including tag, iv and salt.
     * @param {Object} [rp] A returned version with filled-in parameters.
     * @return {Object} The cipher raw data.
     * @throws {sjcl.exception.invalid} if a parameter is invalid.
     */
    _encrypt: function (password, plaintext, params, rp) {
        params = params || {};
        rp = rp || {};
        var j = sjcl.json, p = j._add({ iv: sjcl.random.randomWords(4, 0) }, j.defaults), tmp, prp, adata;
        j._add(p, params);
        adata = p.adata;
        if (typeof p.salt === "string") {
            p.salt = sjcl.codec.base64.toBits(p.salt);
        }
        if (typeof p.iv === "string") {
            p.iv = sjcl.codec.base64.toBits(p.iv);
        }
        if (!sjcl.mode[p.mode] ||
            !sjcl.cipher[p.cipher] ||
            (typeof password === "string" && p.iter <= 100) ||
            (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
            (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
            (p.iv.length < 2 || p.iv.length > 4)) {
            throw new sjcl.exception.invalid("json encrypt: invalid parameters");
        }
        if (typeof password === "string") {
            tmp = sjcl.misc.cachedPbkdf2(password, p);
            password = tmp.key.slice(0, p.ks / 32);
            p.salt = tmp.salt;
        }
        else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.publicKey) {
            tmp = password.kem();
            p.kemtag = tmp.tag;
            password = tmp.key.slice(0, p.ks / 32);
        }
        if (typeof plaintext === "string") {
            plaintext = sjcl.codec.utf8String.toBits(plaintext);
        }
        if (typeof adata === "string") {
            p.adata = adata = sjcl.codec.utf8String.toBits(adata);
        }
        prp = new sjcl.cipher[p.cipher](password);
        /* return the json data */
        j._add(rp, p);
        rp.key = password;
        /* do the encryption */
        if (p.mode === "ccm" && sjcl.arrayBuffer && sjcl.arrayBuffer.ccm && plaintext instanceof ArrayBuffer) {
            p.ct = sjcl.arrayBuffer.ccm.encrypt(prp, plaintext, p.iv, adata, p.ts);
        }
        else {
            p.ct = sjcl.mode[p.mode].encrypt(prp, plaintext, p.iv, adata, p.ts);
        }
        //return j.encode(j._subtract(p, j.defaults));
        return p;
    },
    /** Simple encryption function.
     * @param {String|bitArray} password The password or key.
     * @param {String} plaintext The data to encrypt.
     * @param {Object} [params] The parameters including tag, iv and salt.
     * @param {Object} [rp] A returned version with filled-in parameters.
     * @return {String} The ciphertext serialized data.
     * @throws {sjcl.exception.invalid} if a parameter is invalid.
     */
    encrypt: function (password, plaintext, params, rp) {
        var j = sjcl.json, p = j._encrypt.apply(j, arguments);
        return j.encode(p);
    },
    /** Simple decryption function.
     * @param {String|bitArray} password The password or key.
     * @param {Object} ciphertext The cipher raw data to decrypt.
     * @param {Object} [params] Additional non-default parameters.
     * @param {Object} [rp] A returned object with filled parameters.
     * @return {String} The plaintext.
     * @throws {sjcl.exception.invalid} if a parameter is invalid.
     * @throws {sjcl.exception.corrupt} if the ciphertext is corrupt.
     */
    _decrypt: function (password, ciphertext, params, rp) {
        params = params || {};
        rp = rp || {};
        var j = sjcl.json, p = j._add(j._add(j._add({}, j.defaults), ciphertext), params, true), ct, tmp, prp, adata = p.adata;
        if (typeof p.salt === "string") {
            p.salt = sjcl.codec.base64.toBits(p.salt);
        }
        if (typeof p.iv === "string") {
            p.iv = sjcl.codec.base64.toBits(p.iv);
        }
        if (!sjcl.mode[p.mode] ||
            !sjcl.cipher[p.cipher] ||
            (typeof password === "string" && p.iter <= 100) ||
            (p.ts !== 64 && p.ts !== 96 && p.ts !== 128) ||
            (p.ks !== 128 && p.ks !== 192 && p.ks !== 256) ||
            (!p.iv) ||
            (p.iv.length < 2 || p.iv.length > 4)) {
            throw new sjcl.exception.invalid("json decrypt: invalid parameters");
        }
        if (typeof password === "string") {
            tmp = sjcl.misc.cachedPbkdf2(password, p);
            password = tmp.key.slice(0, p.ks / 32);
            p.salt = tmp.salt;
        }
        else if (sjcl.ecc && password instanceof sjcl.ecc.elGamal.secretKey) {
            password = password.unkem(sjcl.codec.base64.toBits(p.kemtag)).slice(0, p.ks / 32);
        }
        if (typeof adata === "string") {
            adata = sjcl.codec.utf8String.toBits(adata);
        }
        prp = new sjcl.cipher[p.cipher](password);
        /* do the decryption */
        if (p.mode === "ccm" && sjcl.arrayBuffer && sjcl.arrayBuffer.ccm && p.ct instanceof ArrayBuffer) {
            ct = sjcl.arrayBuffer.ccm.decrypt(prp, p.ct, p.iv, p.tag, adata, p.ts);
        }
        else {
            ct = sjcl.mode[p.mode].decrypt(prp, p.ct, p.iv, adata, p.ts);
        }
        /* return the json data */
        j._add(rp, p);
        rp.key = password;
        if (params.raw === 1) {
            return ct;
        }
        else {
            return sjcl.codec.utf8String.fromBits(ct);
        }
    },
    /** Simple decryption function.
     * @param {String|bitArray} password The password or key.
     * @param {String} ciphertext The ciphertext to decrypt.
     * @param {Object} [params] Additional non-default parameters.
     * @param {Object} [rp] A returned object with filled parameters.
     * @return {String} The plaintext.
     * @throws {sjcl.exception.invalid} if a parameter is invalid.
     * @throws {sjcl.exception.corrupt} if the ciphertext is corrupt.
     */
    decrypt: function (password, ciphertext, params, rp) {
        var j = sjcl.json;
        return j._decrypt(password, j.decode(ciphertext), params, rp);
    },
    /** Encode a flat structure into a JSON string.
     * @param {Object} obj The structure to encode.
     * @return {String} A JSON string.
     * @throws {sjcl.exception.invalid} if obj has a non-alphanumeric property.
     * @throws {sjcl.exception.bug} if a parameter has an unsupported type.
     */
    encode: function (obj) {
        var i, out = '{', comma = '';
        for (i in obj) {
            if (obj.hasOwnProperty(i)) {
                if (!i.match(/^[a-z0-9]+$/i)) {
                    throw new sjcl.exception.invalid("json encode: invalid property name");
                }
                out += comma + '"' + i + '":';
                comma = ',';
                switch (typeof obj[i]) {
                    case 'number':
                    case 'boolean':
                        out += obj[i];
                        break;
                    case 'string':
                        out += '"' + escape(obj[i]) + '"';
                        break;
                    case 'object':
                        out += '"' + sjcl.codec.base64.fromBits(obj[i], 0) + '"';
                        break;
                    default:
                        throw new sjcl.exception.bug("json encode: unsupported type");
                }
            }
        }
        return out + '}';
    },
    /** Decode a simple (flat) JSON string into a structure.  The ciphertext,
     * adata, salt and iv will be base64-decoded.
     * @param {String} str The string.
     * @return {Object} The decoded structure.
     * @throws {sjcl.exception.invalid} if str isn't (simple) JSON.
     */
    decode: function (str) {
        str = str.replace(/\s/g, '');
        if (!str.match(/^\{.*\}$/)) {
            throw new sjcl.exception.invalid("json decode: this isn't json!");
        }
        var a = str.replace(/^\{|\}$/g, '').split(/,/), out = {}, i, m;
        for (i = 0; i < a.length; i++) {
            if (!(m = a[i].match(/^\s*(?:(["']?)([a-z][a-z0-9]*)\1)\s*:\s*(?:(-?\d+)|"([a-z0-9+\/%*_.@=\-]*)"|(true|false))$/i))) {
                throw new sjcl.exception.invalid("json decode: this isn't json!");
            }
            if (m[3] != null) {
                out[m[2]] = parseInt(m[3], 10);
            }
            else if (m[4] != null) {
                out[m[2]] = m[2].match(/^(ct|adata|salt|iv)$/) ? sjcl.codec.base64.toBits(m[4]) : unescape(m[4]);
            }
            else if (m[5] != null) {
                out[m[2]] = m[5] === 'true';
            }
        }
        return out;
    },
    /** Insert all elements of src into target, modifying and returning target.
     * @param {Object} target The object to be modified.
     * @param {Object} src The object to pull data from.
     * @param {boolean} [requireSame=false] If true, throw an exception if any field of target differs from corresponding field of src.
     * @return {Object} target.
     * @private
     */
    _add: function (target, src, requireSame) {
        if (target === undefined) {
            target = {};
        }
        if (src === undefined) {
            return target;
        }
        var i;
        for (i in src) {
            if (src.hasOwnProperty(i)) {
                if (requireSame && target[i] !== undefined && target[i] !== src[i]) {
                    throw new sjcl.exception.invalid("required parameter overridden");
                }
                target[i] = src[i];
            }
        }
        return target;
    },
    /** Remove all elements of minus from plus.  Does not modify plus.
     * @private
     */
    _subtract: function (plus, minus) {
        var out = {}, i;
        for (i in plus) {
            if (plus.hasOwnProperty(i) && plus[i] !== minus[i]) {
                out[i] = plus[i];
            }
        }
        return out;
    },
    /** Return only the specified elements of src.
     * @private
     */
    _filter: function (src, filter) {
        var out = {}, i;
        for (i = 0; i < filter.length; i++) {
            if (src[filter[i]] !== undefined) {
                out[filter[i]] = src[filter[i]];
            }
        }
        return out;
    }
};
/** Simple encryption function; convenient shorthand for sjcl.json.encrypt.
 * @param {String|bitArray} password The password or key.
 * @param {String} plaintext The data to encrypt.
 * @param {Object} [params] The parameters including tag, iv and salt.
 * @param {Object} [rp] A returned version with filled-in parameters.
 * @return {String} The ciphertext.
 */
sjcl.encrypt = sjcl.json.encrypt;
/** Simple decryption function; convenient shorthand for sjcl.json.decrypt.
 * @param {String|bitArray} password The password or key.
 * @param {String} ciphertext The ciphertext to decrypt.
 * @param {Object} [params] Additional non-default parameters.
 * @param {Object} [rp] A returned object with filled parameters.
 * @return {String} The plaintext.
 */
sjcl.decrypt = sjcl.json.decrypt;
/** The cache for cachedPbkdf2.
 * @private
 */
sjcl.misc._pbkdf2Cache = {};
/** Cached PBKDF2 key derivation.
 * @param {String} password The password.
 * @param {Object} [obj] The derivation params (iteration count and optional salt).
 * @return {Object} The derived data in key, the salt in salt.
 */
sjcl.misc.cachedPbkdf2 = function (password, obj) {
    var cache = sjcl.misc._pbkdf2Cache, c, cp, salt, iter;
    obj = obj || {};
    iter = obj.iter || 1000;
    /* open the cache for this password and iteration count */
    cp = cache[password] = cache[password] || {};
    c = cp[iter] = cp[iter] || { firstSalt: (obj.salt && obj.salt.length) ?
            obj.salt.slice(0) : sjcl.random.randomWords(2, 0) };
    salt = (obj.salt === undefined) ? c.firstSalt : obj.salt;
    c[salt] = c[salt] || sjcl.misc.pbkdf2(password, salt, obj.iter);
    return { key: c[salt].slice(0), salt: salt.slice(0) };
};
// Thanks to Colin McRae and Jonathan Burns of ionic security
// for reporting and fixing two bugs in this file!
/**
 * Constructs a new bignum from another bignum, a number or a hex string.
 * @constructor
 */
sjcl.bn = function (it) {
    this.initWith(it);
};
sjcl.bn.prototype = {
    radix: 24,
    maxMul: 8,
    _class: sjcl.bn,
    copy: function () {
        return new this._class(this);
    },
    /**
     * Initializes this with it, either as a bn, a number, or a hex string.
     */
    initWith: function (it) {
        var i = 0, k;
        switch (typeof it) {
            case "object":
                this.limbs = it.limbs.slice(0);
                break;
            case "number":
                this.limbs = [it];
                this.normalize();
                break;
            case "string":
                it = it.replace(/^0x/, '');
                this.limbs = [];
                // hack
                k = this.radix / 4;
                for (i = 0; i < it.length; i += k) {
                    this.limbs.push(parseInt(it.substring(Math.max(it.length - i - k, 0), it.length - i), 16));
                }
                break;
            default:
                this.limbs = [0];
        }
        return this;
    },
    /**
     * Returns true if "this" and "that" are equal.  Calls fullReduce().
     * Equality test is in constant time.
     */
    equals: function (that) {
        if (typeof that === "number") {
            that = new this._class(that);
        }
        var difference = 0, i;
        this.fullReduce();
        that.fullReduce();
        for (i = 0; i < this.limbs.length || i < that.limbs.length; i++) {
            difference |= this.getLimb(i) ^ that.getLimb(i);
        }
        return (difference === 0);
    },
    /**
     * Get the i'th limb of this, zero if i is too large.
     */
    getLimb: function (i) {
        return (i >= this.limbs.length) ? 0 : this.limbs[i];
    },
    /**
     * Constant time comparison function.
     * Returns 1 if this >= that, or zero otherwise.
     */
    greaterEquals: function (that) {
        if (typeof that === "number") {
            that = new this._class(that);
        }
        var less = 0, greater = 0, i, a, b;
        i = Math.max(this.limbs.length, that.limbs.length) - 1;
        for (; i >= 0; i--) {
            a = this.getLimb(i);
            b = that.getLimb(i);
            greater |= (b - a) & ~less;
            less |= (a - b) & ~greater;
        }
        return (greater | ~less) >>> 31;
    },
    /**
     * Convert to a hex string.
     */
    toString: function () {
        this.fullReduce();
        var out = "", i, s, l = this.limbs;
        for (i = 0; i < this.limbs.length; i++) {
            s = l[i].toString(16);
            while (i < this.limbs.length - 1 && s.length < 6) {
                s = "0" + s;
            }
            out = s + out;
        }
        return "0x" + out;
    },
    /** this += that.  Does not normalize. */
    addM: function (that) {
        if (typeof (that) !== "object") {
            that = new this._class(that);
        }
        var i, l = this.limbs, ll = that.limbs;
        for (i = l.length; i < ll.length; i++) {
            l[i] = 0;
        }
        for (i = 0; i < ll.length; i++) {
            l[i] += ll[i];
        }
        return this;
    },
    /** this *= 2.  Requires normalized; ends up normalized. */
    doubleM: function () {
        var i, carry = 0, tmp, r = this.radix, m = this.radixMask, l = this.limbs;
        for (i = 0; i < l.length; i++) {
            tmp = l[i];
            tmp = tmp + tmp + carry;
            l[i] = tmp & m;
            carry = tmp >> r;
        }
        if (carry) {
            l.push(carry);
        }
        return this;
    },
    /** this /= 2, rounded down.  Requires normalized; ends up normalized. */
    halveM: function () {
        var i, carry = 0, tmp, r = this.radix, l = this.limbs;
        for (i = l.length - 1; i >= 0; i--) {
            tmp = l[i];
            l[i] = (tmp + carry) >> 1;
            carry = (tmp & 1) << r;
        }
        if (!l[l.length - 1]) {
            l.pop();
        }
        return this;
    },
    /** this -= that.  Does not normalize. */
    subM: function (that) {
        if (typeof (that) !== "object") {
            that = new this._class(that);
        }
        var i, l = this.limbs, ll = that.limbs;
        for (i = l.length; i < ll.length; i++) {
            l[i] = 0;
        }
        for (i = 0; i < ll.length; i++) {
            l[i] -= ll[i];
        }
        return this;
    },
    mod: function (that) {
        var neg = !this.greaterEquals(new sjcl.bn(0));
        that = new sjcl.bn(that).normalize(); // copy before we begin
        var out = new sjcl.bn(this).normalize(), ci = 0;
        if (neg)
            out = (new sjcl.bn(0)).subM(out).normalize();
        for (; out.greaterEquals(that); ci++) {
            that.doubleM();
        }
        if (neg)
            out = that.sub(out).normalize();
        for (; ci > 0; ci--) {
            that.halveM();
            if (out.greaterEquals(that)) {
                out.subM(that).normalize();
            }
        }
        return out.trim();
    },
    /** return inverse mod prime p.  p must be odd. Binary extended Euclidean algorithm mod p. */
    inverseMod: function (p) {
        var a = new sjcl.bn(1), b = new sjcl.bn(0), x = new sjcl.bn(this), y = new sjcl.bn(p), tmp, i, nz = 1;
        if (!(p.limbs[0] & 1)) {
            throw (new sjcl.exception.invalid("inverseMod: p must be odd"));
        }
        // invariant: y is odd
        do {
            if (x.limbs[0] & 1) {
                if (!x.greaterEquals(y)) {
                    // x < y; swap everything
                    tmp = x;
                    x = y;
                    y = tmp;
                    tmp = a;
                    a = b;
                    b = tmp;
                }
                x.subM(y);
                x.normalize();
                if (!a.greaterEquals(b)) {
                    a.addM(p);
                }
                a.subM(b);
            }
            // cut everything in half
            x.halveM();
            if (a.limbs[0] & 1) {
                a.addM(p);
            }
            a.normalize();
            a.halveM();
            // check for termination: x ?= 0
            for (i = nz = 0; i < x.limbs.length; i++) {
                nz |= x.limbs[i];
            }
        } while (nz);
        if (!y.equals(1)) {
            throw (new sjcl.exception.invalid("inverseMod: p and x must be relatively prime"));
        }
        return b;
    },
    /** this + that.  Does not normalize. */
    add: function (that) {
        return this.copy().addM(that);
    },
    /** this - that.  Does not normalize. */
    sub: function (that) {
        return this.copy().subM(that);
    },
    /** this * that.  Normalizes and reduces. */
    mul: function (that) {
        if (typeof (that) === "number") {
            that = new this._class(that);
        }
        else {
            that.normalize();
        }
        this.normalize();
        var i, j, a = this.limbs, b = that.limbs, al = a.length, bl = b.length, out = new this._class(), c = out.limbs, ai, ii = this.maxMul;
        for (i = 0; i < this.limbs.length + that.limbs.length + 1; i++) {
            c[i] = 0;
        }
        for (i = 0; i < al; i++) {
            ai = a[i];
            for (j = 0; j < bl; j++) {
                c[i + j] += ai * b[j];
            }
            if (!--ii) {
                ii = this.maxMul;
                out.cnormalize();
            }
        }
        return out.cnormalize().reduce();
    },
    /** this ^ 2.  Normalizes and reduces. */
    square: function () {
        return this.mul(this);
    },
    /** this ^ n.  Uses square-and-multiply.  Normalizes and reduces. */
    power: function (l) {
        l = new sjcl.bn(l).normalize().trim().limbs;
        var i, j, out = new this._class(1), pow = this;
        for (i = 0; i < l.length; i++) {
            for (j = 0; j < this.radix; j++) {
                if (l[i] & (1 << j)) {
                    out = out.mul(pow);
                }
                if (i == (l.length - 1) && l[i] >> (j + 1) == 0) {
                    break;
                }
                pow = pow.square();
            }
        }
        return out;
    },
    /** this * that mod N */
    mulmod: function (that, N) {
        return this.mod(N).mul(that.mod(N)).mod(N);
    },
    /** this ^ x mod N */
    powermod: function (x, N) {
        x = new sjcl.bn(x);
        N = new sjcl.bn(N);
        // Jump to montpowermod if possible.
        if ((N.limbs[0] & 1) == 1) {
            var montOut = this.montpowermod(x, N);
            if (montOut != false) {
                return montOut;
            } // else go to slow powermod
        }
        var i, j, l = x.normalize().trim().limbs, out = new this._class(1), pow = this;
        for (i = 0; i < l.length; i++) {
            for (j = 0; j < this.radix; j++) {
                if (l[i] & (1 << j)) {
                    out = out.mulmod(pow, N);
                }
                if (i == (l.length - 1) && l[i] >> (j + 1) == 0) {
                    break;
                }
                pow = pow.mulmod(pow, N);
            }
        }
        return out;
    },
    /** this ^ x mod N with Montomery reduction */
    montpowermod: function (x, N) {
        x = new sjcl.bn(x).normalize().trim();
        N = new sjcl.bn(N);
        var i, j, radix = this.radix, out = new this._class(1), pow = this.copy();
        // Generate R as a cap of N.
        var R, s, wind, bitsize = x.bitLength();
        R = new sjcl.bn({
            limbs: N.copy().normalize().trim().limbs.map(function () { return 0; })
        });
        for (s = this.radix; s > 0; s--) {
            if (((N.limbs[N.limbs.length - 1] >> s) & 1) == 1) {
                R.limbs[R.limbs.length - 1] = 1 << s;
                break;
            }
        }
        // Calculate window size as a function of the exponent's size.
        if (bitsize == 0) {
            return this;
        }
        else if (bitsize < 18) {
            wind = 1;
        }
        else if (bitsize < 48) {
            wind = 3;
        }
        else if (bitsize < 144) {
            wind = 4;
        }
        else if (bitsize < 768) {
            wind = 5;
        }
        else {
            wind = 6;
        }
        // Find R' and N' such that R * R' - N * N' = 1.
        var RR = R.copy(), NN = N.copy(), RP = new sjcl.bn(1), NP = new sjcl.bn(0), RT = R.copy();
        while (RT.greaterEquals(1)) {
            RT.halveM();
            if ((RP.limbs[0] & 1) == 0) {
                RP.halveM();
                NP.halveM();
            }
            else {
                RP.addM(NN);
                RP.halveM();
                NP.halveM();
                NP.addM(RR);
            }
        }
        RP = RP.normalize();
        NP = NP.normalize();
        RR.doubleM();
        var R2 = RR.mulmod(RR, N);
        // Check whether the invariant holds.
        // If it doesn't, we can't use Montgomery reduction on this modulus.
        if (!RR.mul(RP).sub(N.mul(NP)).equals(1)) {
            return false;
        }
        var montIn = function (c) { return montMul(c, R2); }, montMul = function (a, b) {
            // Standard Montgomery reduction
            var k, ab, right, abBar, mask = (1 << (s + 1)) - 1;
            ab = a.mul(b);
            right = ab.mul(NP);
            right.limbs = right.limbs.slice(0, R.limbs.length);
            if (right.limbs.length == R.limbs.length) {
                right.limbs[R.limbs.length - 1] &= mask;
            }
            right = right.mul(N);
            abBar = ab.add(right).normalize().trim();
            abBar.limbs = abBar.limbs.slice(R.limbs.length - 1);
            // Division.  Equivelent to calling *.halveM() s times.
            for (k = 0; k < abBar.limbs.length; k++) {
                if (k > 0) {
                    abBar.limbs[k - 1] |= (abBar.limbs[k] & mask) << (radix - s - 1);
                }
                abBar.limbs[k] = abBar.limbs[k] >> (s + 1);
            }
            if (abBar.greaterEquals(N)) {
                abBar.subM(N);
            }
            return abBar;
        }, montOut = function (c) { return montMul(c, 1); };
        pow = montIn(pow);
        out = montIn(out);
        // Sliding-Window Exponentiation (HAC 14.85)
        var h, precomp = {}, cap = (1 << (wind - 1)) - 1;
        precomp[1] = pow.copy();
        precomp[2] = montMul(pow, pow);
        for (h = 1; h <= cap; h++) {
            precomp[(2 * h) + 1] = montMul(precomp[(2 * h) - 1], precomp[2]);
        }
        var getBit = function (exp, i) {
            var off = i % exp.radix;
            return (exp.limbs[Math.floor(i / exp.radix)] & (1 << off)) >> off;
        };
        for (i = x.bitLength() - 1; i >= 0;) {
            if (getBit(x, i) == 0) {
                // If the next bit is zero:
                //   Square, move forward one bit.
                out = montMul(out, out);
                i = i - 1;
            }
            else {
                // If the next bit is one:
                //   Find the longest sequence of bits after this one, less than `wind`
                //   bits long, that ends with a 1.  Convert the sequence into an
                //   integer and look up the pre-computed value to add.
                var l = i - wind + 1;
                while (getBit(x, l) == 0) {
                    l++;
                }
                var indx = 0;
                for (j = l; j <= i; j++) {
                    indx += getBit(x, j) << (j - l);
                    out = montMul(out, out);
                }
                out = montMul(out, precomp[indx]);
                i = l - 1;
            }
        }
        return montOut(out);
    },
    trim: function () {
        var l = this.limbs, p;
        do {
            p = l.pop();
        } while (l.length && p === 0);
        l.push(p);
        return this;
    },
    /** Reduce mod a modulus.  Stubbed for subclassing. */
    reduce: function () {
        return this;
    },
    /** Reduce and normalize. */
    fullReduce: function () {
        return this.normalize();
    },
    /** Propagate carries. */
    normalize: function () {
        var carry = 0, i, pv = this.placeVal, ipv = this.ipv, l, m, limbs = this.limbs, ll = limbs.length, mask = this.radixMask;
        for (i = 0; i < ll || (carry !== 0 && carry !== -1); i++) {
            l = (limbs[i] || 0) + carry;
            m = limbs[i] = l & mask;
            carry = (l - m) * ipv;
        }
        if (carry === -1) {
            limbs[i - 1] -= pv;
        }
        this.trim();
        return this;
    },
    /** Constant-time normalize. Does not allocate additional space. */
    cnormalize: function () {
        var carry = 0, i, ipv = this.ipv, l, m, limbs = this.limbs, ll = limbs.length, mask = this.radixMask;
        for (i = 0; i < ll - 1; i++) {
            l = limbs[i] + carry;
            m = limbs[i] = l & mask;
            carry = (l - m) * ipv;
        }
        limbs[i] += carry;
        return this;
    },
    /** Serialize to a bit array */
    toBits: function (len) {
        this.fullReduce();
        len = len || this.exponent || this.bitLength();
        var i = Math.floor((len - 1) / 24), w = sjcl.bitArray, e = (len + 7 & -8) % this.radix || this.radix, out = [w.partial(e, this.getLimb(i))];
        for (i--; i >= 0; i--) {
            out = w.concat(out, [w.partial(Math.min(this.radix, len), this.getLimb(i))]);
            len -= this.radix;
        }
        return out;
    },
    /** Return the length in bits, rounded up to the nearest byte. */
    bitLength: function () {
        this.fullReduce();
        var out = this.radix * (this.limbs.length - 1), b = this.limbs[this.limbs.length - 1];
        for (; b; b >>>= 1) {
            out++;
        }
        return out + 7 & -8;
    }
};
/** @memberOf sjcl.bn
* @this { sjcl.bn }
*/
sjcl.bn.fromBits = function (bits) {
    var Class = this, out = new Class(), words = [], w = sjcl.bitArray, t = this.prototype, l = Math.min(this.bitLength || 0x100000000, w.bitLength(bits)), e = l % t.radix || t.radix;
    words[0] = w.extract(bits, 0, e);
    for (; e < l; e += t.radix) {
        words.unshift(w.extract(bits, e, t.radix));
    }
    out.limbs = words;
    return out;
};
sjcl.bn.prototype.ipv = 1 / (sjcl.bn.prototype.placeVal = Math.pow(2, sjcl.bn.prototype.radix));
sjcl.bn.prototype.radixMask = (1 << sjcl.bn.prototype.radix) - 1;
/**
 * Creates a new subclass of bn, based on reduction modulo a pseudo-Mersenne prime,
 * i.e. a prime of the form 2^e + sum(a * 2^b),where the sum is negative and sparse.
 */
sjcl.bn.pseudoMersennePrime = function (exponent, coeff) {
    /** @constructor
    * @private
    */
    function p(it) {
        this.initWith(it);
        /*if (this.limbs[this.modOffset]) {
          this.reduce();
        }*/
    }
    var ppr = p.prototype = new sjcl.bn(), i, tmp, mo;
    mo = ppr.modOffset = Math.ceil(tmp = exponent / ppr.radix);
    ppr.exponent = exponent;
    ppr.offset = [];
    ppr.factor = [];
    ppr.minOffset = mo;
    ppr.fullMask = 0;
    ppr.fullOffset = [];
    ppr.fullFactor = [];
    ppr.modulus = p.modulus = new sjcl.bn(Math.pow(2, exponent));
    ppr.fullMask = 0 | -Math.pow(2, exponent % ppr.radix);
    for (i = 0; i < coeff.length; i++) {
        ppr.offset[i] = Math.floor(coeff[i][0] / ppr.radix - tmp);
        ppr.fullOffset[i] = Math.floor(coeff[i][0] / ppr.radix) - mo + 1;
        ppr.factor[i] = coeff[i][1] * Math.pow(1 / 2, exponent - coeff[i][0] + ppr.offset[i] * ppr.radix);
        ppr.fullFactor[i] = coeff[i][1] * Math.pow(1 / 2, exponent - coeff[i][0] + ppr.fullOffset[i] * ppr.radix);
        ppr.modulus.addM(new sjcl.bn(Math.pow(2, coeff[i][0]) * coeff[i][1]));
        ppr.minOffset = Math.min(ppr.minOffset, -ppr.offset[i]); // conservative
    }
    ppr._class = p;
    ppr.modulus.cnormalize();
    /** Approximate reduction mod p.  May leave a number which is negative or slightly larger than p.
     * @memberof sjcl.bn
     * @this { sjcl.bn }
     */
    ppr.reduce = function () {
        var i, k, l, mo = this.modOffset, limbs = this.limbs, off = this.offset, ol = this.offset.length, fac = this.factor, ll;
        i = this.minOffset;
        while (limbs.length > mo) {
            l = limbs.pop();
            ll = limbs.length;
            for (k = 0; k < ol; k++) {
                limbs[ll + off[k]] -= fac[k] * l;
            }
            i--;
            if (!i) {
                limbs.push(0);
                this.cnormalize();
                i = this.minOffset;
            }
        }
        this.cnormalize();
        return this;
    };
    /** @memberof sjcl.bn
    * @this { sjcl.bn }
    */
    ppr._strongReduce = (ppr.fullMask === -1) ? ppr.reduce : function () {
        var limbs = this.limbs, i = limbs.length - 1, k, l;
        this.reduce();
        if (i === this.modOffset - 1) {
            l = limbs[i] & this.fullMask;
            limbs[i] -= l;
            for (k = 0; k < this.fullOffset.length; k++) {
                limbs[i + this.fullOffset[k]] -= this.fullFactor[k] * l;
            }
            this.normalize();
        }
    };
    /** mostly constant-time, very expensive full reduction.
     * @memberof sjcl.bn
     * @this { sjcl.bn }
     */
    ppr.fullReduce = function () {
        var greater, i;
        // massively above the modulus, may be negative
        this._strongReduce();
        // less than twice the modulus, may be negative
        this.addM(this.modulus);
        this.addM(this.modulus);
        this.normalize();
        // probably 2-3x the modulus
        this._strongReduce();
        // less than the power of 2.  still may be more than
        // the modulus
        // HACK: pad out to this length
        for (i = this.limbs.length; i < this.modOffset; i++) {
            this.limbs[i] = 0;
        }
        // constant-time subtract modulus
        greater = this.greaterEquals(this.modulus);
        for (i = 0; i < this.limbs.length; i++) {
            this.limbs[i] -= this.modulus.limbs[i] * greater;
        }
        this.cnormalize();
        return this;
    };
    /** @memberof sjcl.bn
    * @this { sjcl.bn }
    */
    ppr.inverse = function () {
        return (this.power(this.modulus.sub(2)));
    };
    p.fromBits = sjcl.bn.fromBits;
    return p;
};
// a small Mersenne prime
var sbp = sjcl.bn.pseudoMersennePrime;
sjcl.bn.prime = {
    p127: sbp(127, [[0, -1]]),
    // Bernstein's prime for Curve25519
    p25519: sbp(255, [[0, -19]]),
    // Koblitz primes
    p192k: sbp(192, [[32, -1], [12, -1], [8, -1], [7, -1], [6, -1], [3, -1], [0, -1]]),
    p224k: sbp(224, [[32, -1], [12, -1], [11, -1], [9, -1], [7, -1], [4, -1], [1, -1], [0, -1]]),
    p256k: sbp(256, [[32, -1], [9, -1], [8, -1], [7, -1], [6, -1], [4, -1], [0, -1]]),
    // NIST primes
    p192: sbp(192, [[0, -1], [64, -1]]),
    p224: sbp(224, [[0, 1], [96, -1]]),
    p256: sbp(256, [[0, -1], [96, 1], [192, 1], [224, -1]]),
    p384: sbp(384, [[0, -1], [32, 1], [96, -1], [128, -1]]),
    p521: sbp(521, [[0, -1]])
};
sjcl.bn.random = function (modulus, paranoia) {
    if (typeof modulus !== "object") {
        modulus = new sjcl.bn(modulus);
    }
    var words, i, l = modulus.limbs.length, m = modulus.limbs[l - 1] + 1, out = new sjcl.bn();
    while (true) {
        // get a sequence whose first digits make sense
        do {
            words = sjcl.random.randomWords(l, paranoia);
            if (words[l - 1] < 0) {
                words[l - 1] += 0x100000000;
            }
        } while (Math.floor(words[l - 1] / m) === Math.floor(0x100000000 / m));
        words[l - 1] %= m;
        // mask off all the limbs
        for (i = 0; i < l - 1; i++) {
            words[i] &= modulus.radixMask;
        }
        // check the rest of the digitssj
        out.limbs = words;
        if (!out.greaterEquals(modulus)) {
            return out;
        }
    }
};
/**
 * base class for all ecc operations.
 * @namespace
 */
sjcl.ecc = {};
/**
 * Represents a point on a curve in affine coordinates.
 * @constructor
 * @param {sjcl.ecc.curve} curve The curve that this point lies on.
 * @param {bigInt} x The x coordinate.
 * @param {bigInt} y The y coordinate.
 */
sjcl.ecc.point = function (curve, x, y) {
    if (x === undefined) {
        this.isIdentity = true;
    }
    else {
        if (x instanceof sjcl.bn) {
            x = new curve.field(x);
        }
        if (y instanceof sjcl.bn) {
            y = new curve.field(y);
        }
        this.x = x;
        this.y = y;
        this.isIdentity = false;
    }
    this.curve = curve;
};
sjcl.ecc.point.prototype = {
    toJac: function () {
        return new sjcl.ecc.pointJac(this.curve, this.x, this.y, new this.curve.field(1));
    },
    mult: function (k) {
        return this.toJac().mult(k, this).toAffine();
    },
    /**
     * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
     * @param {bigInt} k The coefficient to multiply this by.
     * @param {bigInt} k2 The coefficient to multiply affine2 this by.
     * @param {sjcl.ecc.point} affine The other point in affine coordinates.
     * @return {sjcl.ecc.pointJac} The result of the multiplication and addition, in Jacobian coordinates.
     */
    mult2: function (k, k2, affine2) {
        return this.toJac().mult2(k, this, k2, affine2).toAffine();
    },
    multiples: function () {
        var m, i, j;
        if (this._multiples === undefined) {
            j = this.toJac().doubl();
            m = this._multiples = [new sjcl.ecc.point(this.curve), this, j.toAffine()];
            for (i = 3; i < 16; i++) {
                j = j.add(this);
                m.push(j.toAffine());
            }
        }
        return this._multiples;
    },
    negate: function () {
        var newY = new this.curve.field(0).sub(this.y).normalize().reduce();
        return new sjcl.ecc.point(this.curve, this.x, newY);
    },
    isValid: function () {
        return this.y.square().equals(this.curve.b.add(this.x.mul(this.curve.a.add(this.x.square()))));
    },
    toBits: function () {
        return sjcl.bitArray.concat(this.x.toBits(), this.y.toBits());
    }
};
/**
 * Represents a point on a curve in Jacobian coordinates. Coordinates can be specified as bigInts or strings (which
 * will be converted to bigInts).
 *
 * @constructor
 * @param {bigInt/string} x The x coordinate.
 * @param {bigInt/string} y The y coordinate.
 * @param {bigInt/string} z The z coordinate.
 * @param {sjcl.ecc.curve} curve The curve that this point lies on.
 */
sjcl.ecc.pointJac = function (curve, x, y, z) {
    if (x === undefined) {
        this.isIdentity = true;
    }
    else {
        this.x = x;
        this.y = y;
        this.z = z;
        this.isIdentity = false;
    }
    this.curve = curve;
};
sjcl.ecc.pointJac.prototype = {
    /**
     * Adds S and T and returns the result in Jacobian coordinates. Note that S must be in Jacobian coordinates and T must be in affine coordinates.
     * @param {sjcl.ecc.pointJac} S One of the points to add, in Jacobian coordinates.
     * @param {sjcl.ecc.point} T The other point to add, in affine coordinates.
     * @return {sjcl.ecc.pointJac} The sum of the two points, in Jacobian coordinates.
     */
    add: function (T) {
        var S = this, sz2, c, d, c2, x1, x2, x, y1, y2, y, z;
        if (S.curve !== T.curve) {
            throw new sjcl.exception.invalid("sjcl.ecc.add(): Points must be on the same curve to add them!");
        }
        if (S.isIdentity) {
            return T.toJac();
        }
        else if (T.isIdentity) {
            return S;
        }
        sz2 = S.z.square();
        c = T.x.mul(sz2).subM(S.x);
        if (c.equals(0)) {
            if (S.y.equals(T.y.mul(sz2.mul(S.z)))) {
                // same point
                return S.doubl();
            }
            else {
                // inverses
                return new sjcl.ecc.pointJac(S.curve);
            }
        }
        d = T.y.mul(sz2.mul(S.z)).subM(S.y);
        c2 = c.square();
        x1 = d.square();
        x2 = c.square().mul(c).addM(S.x.add(S.x).mul(c2));
        x = x1.subM(x2);
        y1 = S.x.mul(c2).subM(x).mul(d);
        y2 = S.y.mul(c.square().mul(c));
        y = y1.subM(y2);
        z = S.z.mul(c);
        return new sjcl.ecc.pointJac(this.curve, x, y, z);
    },
    /**
     * doubles this point.
     * @return {sjcl.ecc.pointJac} The doubled point.
     */
    doubl: function () {
        if (this.isIdentity) {
            return this;
        }
        var y2 = this.y.square(), a = y2.mul(this.x.mul(4)), b = y2.square().mul(8), z2 = this.z.square(), c = this.curve.a.toString() == (new sjcl.bn(-3)).toString() ?
            this.x.sub(z2).mul(3).mul(this.x.add(z2)) :
            this.x.square().mul(3).add(z2.square().mul(this.curve.a)), x = c.square().subM(a).subM(a), y = a.sub(x).mul(c).subM(b), z = this.y.add(this.y).mul(this.z);
        return new sjcl.ecc.pointJac(this.curve, x, y, z);
    },
    /**
     * Returns a copy of this point converted to affine coordinates.
     * @return {sjcl.ecc.point} The converted point.
     */
    toAffine: function () {
        if (this.isIdentity || this.z.equals(0)) {
            return new sjcl.ecc.point(this.curve);
        }
        var zi = this.z.inverse(), zi2 = zi.square();
        return new sjcl.ecc.point(this.curve, this.x.mul(zi2).fullReduce(), this.y.mul(zi2.mul(zi)).fullReduce());
    },
    /**
     * Multiply this point by k and return the answer in Jacobian coordinates.
     * @param {bigInt} k The coefficient to multiply by.
     * @param {sjcl.ecc.point} affine This point in affine coordinates.
     * @return {sjcl.ecc.pointJac} The result of the multiplication, in Jacobian coordinates.
     */
    mult: function (k, affine) {
        if (typeof (k) === "number") {
            k = [k];
        }
        else if (k.limbs !== undefined) {
            k = k.normalize().limbs;
        }
        var i, j, out = new sjcl.ecc.point(this.curve).toJac(), multiples = affine.multiples();
        for (i = k.length - 1; i >= 0; i--) {
            for (j = sjcl.bn.prototype.radix - 4; j >= 0; j -= 4) {
                out = out.doubl().doubl().doubl().doubl().add(multiples[k[i] >> j & 0xF]);
            }
        }
        return out;
    },
    /**
     * Multiply this point by k, added to affine2*k2, and return the answer in Jacobian coordinates.
     * @param {bigInt} k The coefficient to multiply this by.
     * @param {sjcl.ecc.point} affine This point in affine coordinates.
     * @param {bigInt} k2 The coefficient to multiply affine2 this by.
     * @param {sjcl.ecc.point} affine The other point in affine coordinates.
     * @return {sjcl.ecc.pointJac} The result of the multiplication and addition, in Jacobian coordinates.
     */
    mult2: function (k1, affine, k2, affine2) {
        if (typeof (k1) === "number") {
            k1 = [k1];
        }
        else if (k1.limbs !== undefined) {
            k1 = k1.normalize().limbs;
        }
        if (typeof (k2) === "number") {
            k2 = [k2];
        }
        else if (k2.limbs !== undefined) {
            k2 = k2.normalize().limbs;
        }
        var i, j, out = new sjcl.ecc.point(this.curve).toJac(), m1 = affine.multiples(), m2 = affine2.multiples(), l1, l2;
        for (i = Math.max(k1.length, k2.length) - 1; i >= 0; i--) {
            l1 = k1[i] | 0;
            l2 = k2[i] | 0;
            for (j = sjcl.bn.prototype.radix - 4; j >= 0; j -= 4) {
                out = out.doubl().doubl().doubl().doubl().add(m1[l1 >> j & 0xF]).add(m2[l2 >> j & 0xF]);
            }
        }
        return out;
    },
    negate: function () {
        return this.toAffine().negate().toJac();
    },
    isValid: function () {
        var z2 = this.z.square(), z4 = z2.square(), z6 = z4.mul(z2);
        return this.y.square().equals(this.curve.b.mul(z6).add(this.x.mul(this.curve.a.mul(z4).add(this.x.square()))));
    }
};
/**
 * Construct an elliptic curve. Most users will not use this and instead start with one of the NIST curves defined below.
 *
 * @constructor
 * @param {bigInt} p The prime modulus.
 * @param {bigInt} r The prime order of the curve.
 * @param {bigInt} a The constant a in the equation of the curve y^2 = x^3 + ax + b (for NIST curves, a is always -3).
 * @param {bigInt} x The x coordinate of a base point of the curve.
 * @param {bigInt} y The y coordinate of a base point of the curve.
 */
sjcl.ecc.curve = function (Field, r, a, b, x, y) {
    this.field = Field;
    this.r = new sjcl.bn(r);
    this.a = new Field(a);
    this.b = new Field(b);
    this.G = new sjcl.ecc.point(this, new Field(x), new Field(y));
};
sjcl.ecc.curve.prototype.fromBits = function (bits) {
    var w = sjcl.bitArray, l = this.field.prototype.exponent + 7 & -8, p = new sjcl.ecc.point(this, this.field.fromBits(w.bitSlice(bits, 0, l)), this.field.fromBits(w.bitSlice(bits, l, 2 * l)));
    if (!p.isValid()) {
        throw new sjcl.exception.corrupt("not on the curve!");
    }
    return p;
};
sjcl.ecc.curves = {
    c192: new sjcl.ecc.curve(sjcl.bn.prime.p192, "0xffffffffffffffffffffffff99def836146bc9b1b4d22831", -3, "0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", "0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", "0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811"),
    c224: new sjcl.ecc.curve(sjcl.bn.prime.p224, "0xffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", -3, "0xb4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", "0xb70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", "0xbd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34"),
    c256: new sjcl.ecc.curve(sjcl.bn.prime.p256, "0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", -3, "0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", "0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", "0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    c384: new sjcl.ecc.curve(sjcl.bn.prime.p384, "0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", -3, "0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", "0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", "0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f"),
    c521: new sjcl.ecc.curve(sjcl.bn.prime.p521, "0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", -3, "0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00", "0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66", "0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"),
    k192: new sjcl.ecc.curve(sjcl.bn.prime.p192k, "0xfffffffffffffffffffffffe26f2fc170f69466a74defd8d", 0, 3, "0xdb4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d", "0x9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d"),
    k224: new sjcl.ecc.curve(sjcl.bn.prime.p224k, "0x010000000000000000000000000001dce8d2ec6184caf0a971769fb1f7", 0, 5, "0xa1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c", "0x7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5"),
    k256: new sjcl.ecc.curve(sjcl.bn.prime.p256k, "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 0, 7, "0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
};
sjcl.ecc.curveName = function (curve) {
    var curcurve;
    for (curcurve in sjcl.ecc.curves) {
        if (sjcl.ecc.curves.hasOwnProperty(curcurve)) {
            if (sjcl.ecc.curves[curcurve] === curve) {
                return curcurve;
            }
        }
    }
    throw new sjcl.exception.invalid("no such curve");
};
sjcl.ecc.deserialize = function (key) {
    var types = ["elGamal", "ecdsa"];
    if (!key || !key.curve || !sjcl.ecc.curves[key.curve]) {
        throw new sjcl.exception.invalid("invalid serialization");
    }
    if (types.indexOf(key.type) === -1) {
        throw new sjcl.exception.invalid("invalid type");
    }
    var curve = sjcl.ecc.curves[key.curve];
    if (key.secretKey) {
        if (!key.exponent) {
            throw new sjcl.exception.invalid("invalid exponent");
        }
        var exponent = new sjcl.bn(key.exponent);
        return new sjcl.ecc[key.type].secretKey(curve, exponent);
    }
    else {
        if (!key.point) {
            throw new sjcl.exception.invalid("invalid point");
        }
        var point = curve.fromBits(sjcl.codec.hex.toBits(key.point));
        return new sjcl.ecc[key.type].publicKey(curve, point);
    }
};
/** our basicKey classes
*/
sjcl.ecc.basicKey = {
    /** ecc publicKey.
    * @constructor
    * @param {curve} curve the elliptic curve
    * @param {point} point the point on the curve
    */
    publicKey: function (curve, point) {
        this._curve = curve;
        this._curveBitLength = curve.r.bitLength();
        if (point instanceof Array) {
            this._point = curve.fromBits(point);
        }
        else {
            this._point = point;
        }
        this.serialize = function () {
            var curveName = sjcl.ecc.curveName(curve);
            return {
                type: this.getType(),
                secretKey: false,
                point: sjcl.codec.hex.fromBits(this._point.toBits()),
                curve: curveName
            };
        };
        /** get this keys point data
        * @return x and y as bitArrays
        */
        this.get = function () {
            var pointbits = this._point.toBits();
            var len = sjcl.bitArray.bitLength(pointbits);
            var x = sjcl.bitArray.bitSlice(pointbits, 0, len / 2);
            var y = sjcl.bitArray.bitSlice(pointbits, len / 2);
            return { x: x, y: y };
        };
    },
    /** ecc secretKey
    * @constructor
    * @param {curve} curve the elliptic curve
    * @param exponent
    */
    secretKey: function (curve, exponent) {
        this._curve = curve;
        this._curveBitLength = curve.r.bitLength();
        this._exponent = exponent;
        this.serialize = function () {
            var exponent = this.get();
            var curveName = sjcl.ecc.curveName(curve);
            return {
                type: this.getType(),
                secretKey: true,
                exponent: sjcl.codec.hex.fromBits(exponent),
                curve: curveName
            };
        };
        /** get this keys exponent data
        * @return {bitArray} exponent
        */
        this.get = function () {
            return this._exponent.toBits();
        };
    }
};
/** @private */
sjcl.ecc.basicKey.generateKeys = function (cn) {
    return function generateKeys(curve, paranoia, sec) {
        curve = curve || 256;
        if (typeof curve === "number") {
            curve = sjcl.ecc.curves['c' + curve];
            if (curve === undefined) {
                throw new sjcl.exception.invalid("no such curve");
            }
        }
        sec = sec || sjcl.bn.random(curve.r, paranoia);
        var pub = curve.G.mult(sec);
        return { pub: new sjcl.ecc[cn].publicKey(curve, pub),
            sec: new sjcl.ecc[cn].secretKey(curve, sec) };
    };
};
/** elGamal keys */
sjcl.ecc.elGamal = {
    /** generate keys
    * @function
    * @param curve
    * @param {int} paranoia Paranoia for generation (default 6)
    * @param {secretKey} sec secret Key to use. used to get the publicKey for ones secretKey
    */
    generateKeys: sjcl.ecc.basicKey.generateKeys("elGamal"),
    /** elGamal publicKey.
    * @constructor
    * @augments sjcl.ecc.basicKey.publicKey
    */
    publicKey: function (curve, point) {
        sjcl.ecc.basicKey.publicKey.apply(this, arguments);
    },
    /** elGamal secretKey
    * @constructor
    * @augments sjcl.ecc.basicKey.secretKey
    */
    secretKey: function (curve, exponent) {
        sjcl.ecc.basicKey.secretKey.apply(this, arguments);
    }
};
sjcl.ecc.elGamal.publicKey.prototype = {
    /** Kem function of elGamal Public Key
    * @param paranoia paranoia to use for randomization.
    * @return {object} key and tag. unkem(tag) with the corresponding secret key results in the key returned.
    */
    kem: function (paranoia) {
        var sec = sjcl.bn.random(this._curve.r, paranoia), tag = this._curve.G.mult(sec).toBits(), key = sjcl.hash.sha256.hash(this._point.mult(sec).toBits());
        return { key: key, tag: tag };
    },
    getType: function () {
        return "elGamal";
    }
};
sjcl.ecc.elGamal.secretKey.prototype = {
    /** UnKem function of elGamal Secret Key
    * @param {bitArray} tag The Tag to decrypt.
    * @return {bitArray} decrypted key.
    */
    unkem: function (tag) {
        return sjcl.hash.sha256.hash(this._curve.fromBits(tag).mult(this._exponent).toBits());
    },
    /** Diffie-Hellmann function
    * @param {elGamal.publicKey} pk The Public Key to do Diffie-Hellmann with
    * @return {bitArray} diffie-hellmann result for this key combination.
    */
    dh: function (pk) {
        return sjcl.hash.sha256.hash(pk._point.mult(this._exponent).toBits());
    },
    /** Diffie-Hellmann function, compatible with Java generateSecret
    * @param {elGamal.publicKey} pk The Public Key to do Diffie-Hellmann with
    * @return {bitArray} undigested X value, diffie-hellmann result for this key combination,
    * compatible with Java generateSecret().
    */
    dhJavaEc: function (pk) {
        return pk._point.mult(this._exponent).x.toBits();
    },
    getType: function () {
        return "elGamal";
    }
};
/** ecdsa keys */
sjcl.ecc.ecdsa = {
    /** generate keys
    * @function
    * @param curve
    * @param {int} paranoia Paranoia for generation (default 6)
    * @param {secretKey} sec secret Key to use. used to get the publicKey for ones secretKey
    */
    generateKeys: sjcl.ecc.basicKey.generateKeys("ecdsa")
};
/** ecdsa publicKey.
* @constructor
* @augments sjcl.ecc.basicKey.publicKey
*/
sjcl.ecc.ecdsa.publicKey = function (curve, point) {
    sjcl.ecc.basicKey.publicKey.apply(this, arguments);
};
/** specific functions for ecdsa publicKey. */
sjcl.ecc.ecdsa.publicKey.prototype = {
    /** Diffie-Hellmann function
    * @param {bitArray} hash hash to verify.
    * @param {bitArray} rs signature bitArray.
    * @param {boolean}  fakeLegacyVersion use old legacy version
    */
    verify: function (hash, rs, fakeLegacyVersion) {
        if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
            hash = sjcl.bitArray.clamp(hash, this._curveBitLength);
        }
        var w = sjcl.bitArray, R = this._curve.r, l = this._curveBitLength, r = sjcl.bn.fromBits(w.bitSlice(rs, 0, l)), ss = sjcl.bn.fromBits(w.bitSlice(rs, l, 2 * l)), s = fakeLegacyVersion ? ss : ss.inverseMod(R), hG = sjcl.bn.fromBits(hash).mul(s).mod(R), hA = r.mul(s).mod(R), r2 = this._curve.G.mult2(hG, hA, this._point).x;
        if (r.equals(0) || ss.equals(0) || r.greaterEquals(R) || ss.greaterEquals(R) || !r2.equals(r)) {
            if (fakeLegacyVersion === undefined) {
                return this.verify(hash, rs, true);
            }
            else {
                throw (new sjcl.exception.corrupt("signature didn't check out"));
            }
        }
        return true;
    },
    getType: function () {
        return "ecdsa";
    }
};
/** ecdsa secretKey
* @constructor
* @augments sjcl.ecc.basicKey.publicKey
*/
sjcl.ecc.ecdsa.secretKey = function (curve, exponent) {
    sjcl.ecc.basicKey.secretKey.apply(this, arguments);
};
/** specific functions for ecdsa secretKey. */
sjcl.ecc.ecdsa.secretKey.prototype = {
    /** Diffie-Hellmann function
    * @param {bitArray} hash hash to sign.
    * @param {int} paranoia paranoia for random number generation
    * @param {boolean} fakeLegacyVersion use old legacy version
    */
    sign: function (hash, paranoia, fakeLegacyVersion, fixedKForTesting) {
        if (sjcl.bitArray.bitLength(hash) > this._curveBitLength) {
            hash = sjcl.bitArray.clamp(hash, this._curveBitLength);
        }
        var R = this._curve.r, l = R.bitLength(), k = fixedKForTesting || sjcl.bn.random(R.sub(1), paranoia).add(1), r = this._curve.G.mult(k).x.mod(R), ss = sjcl.bn.fromBits(hash).add(r.mul(this._exponent)), s = fakeLegacyVersion ? ss.inverseMod(R).mul(k).mod(R)
            : ss.mul(k.inverseMod(R)).mod(R);
        return sjcl.bitArray.concat(r.toBits(l), s.toBits(l));
    },
    getType: function () {
        return "ecdsa";
    }
};
/** @fileOverview Bit array codec implementations.
 *
 * @author Marco Munizaga
 */
//patch arraybuffers if they don't exist
if (typeof (ArrayBuffer) === 'undefined') {
    (function (globals) {
        globals.ArrayBuffer = function () { };
        globals.DataView = function () { };
    }(this));
}
/**
 * ArrayBuffer
 * @namespace
 */
sjcl.codec.arrayBuffer = {
    /** Convert from a bitArray to an ArrayBuffer.
     * Will default to 8byte padding if padding is undefined*/
    fromBits: function (arr, padding, padding_count) {
        var out, i, ol, tmp, smallest;
        padding = padding == undefined ? true : padding;
        padding_count = padding_count || 8;
        if (arr.length === 0) {
            return new ArrayBuffer(0);
        }
        ol = sjcl.bitArray.bitLength(arr) / 8;
        //check to make sure the bitLength is divisible by 8, if it isn't 
        //we can't do anything since arraybuffers work with bytes, not bits
        if (sjcl.bitArray.bitLength(arr) % 8 !== 0) {
            throw new sjcl.exception.invalid("Invalid bit size, must be divisble by 8 to fit in an arraybuffer correctly");
        }
        if (padding && ol % padding_count !== 0) {
            ol += padding_count - (ol % padding_count);
        }
        //padded temp for easy copying
        tmp = new DataView(new ArrayBuffer(arr.length * 4));
        for (i = 0; i < arr.length; i++) {
            tmp.setUint32(i * 4, (arr[i] << 32)); //get rid of the higher bits
        }
        //now copy the final message if we are not going to 0 pad
        out = new DataView(new ArrayBuffer(ol));
        //save a step when the tmp and out bytelength are ===
        if (out.byteLength === tmp.byteLength) {
            return tmp.buffer;
        }
        smallest = tmp.byteLength < out.byteLength ? tmp.byteLength : out.byteLength;
        for (i = 0; i < smallest; i++) {
            out.setUint8(i, tmp.getUint8(i));
        }
        return out.buffer;
    },
    /** Convert from an ArrayBuffer to a bitArray. */
    toBits: function (buffer) {
        var i, out = [], len, inView, tmp;
        if (buffer.byteLength === 0) {
            return [];
        }
        inView = new DataView(buffer);
        len = inView.byteLength - inView.byteLength % 4;
        for (var i = 0; i < len; i += 4) {
            out.push(inView.getUint32(i));
        }
        if (inView.byteLength % 4 != 0) {
            tmp = new DataView(new ArrayBuffer(4));
            for (var i = 0, l = inView.byteLength % 4; i < l; i++) {
                //we want the data to the right, because partial slices off the starting bits
                tmp.setUint8(i + 4 - l, inView.getUint8(len + i)); // big-endian, 
            }
            out.push(sjcl.bitArray.partial((inView.byteLength % 4) * 8, tmp.getUint32(0)));
        }
        return out;
    },
    /** Prints a hex output of the buffer contents, akin to hexdump **/
    hexDumpBuffer: function (buffer) {
        var stringBufferView = new DataView(buffer);
        var string = '';
        var pad = function (n, width) {
            n = n + '';
            return n.length >= width ? n : new Array(width - n.length + 1).join('0') + n;
        };
        for (var i = 0; i < stringBufferView.byteLength; i += 2) {
            if (i % 16 == 0)
                string += ('\n' + (i).toString(16) + '\t');
            string += (pad(stringBufferView.getUint16(i).toString(16), 4) + ' ');
        }
        if (typeof console === undefined) {
            console = console || { log: function () { } }; //fix for IE
        }
        console.log(string.toUpperCase());
    }
};
if (typeof module !== 'undefined' && module.exports) {
    module.exports = sjcl;
}
if (typeof define === "function") {
    define([], function () {
        return sjcl;
    });
}

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
class SerializedElt extends Uint8Array {
    constructor() {
        super(...arguments);
        this._serializedEltBrand = '';
    }
}
class SerializedScalar extends Uint8Array {
    constructor() {
        super(...arguments);
        this._serializedScalarBrand = '';
    }
}
async function expandXMD(hash, msg, dst, numBytes) {
    const { outLenBytes, blockLenBytes } = hashParams(hash), ell = Math.ceil(numBytes / outLenBytes);
    if (ell > 255) {
        throw new Error('too big');
    }
    let dstPrime = dst;
    if (dst.length > 255) {
        const te = new TextEncoder(), input = joinAll$1([te.encode('H2C-OVERSIZE-DST-'), dst]);
        dstPrime = new Uint8Array(await crypto.subtle.digest(hash, input));
    }
    dstPrime = joinAll$1([dstPrime, new Uint8Array([dstPrime.length])]);
    const zPad = new Uint8Array(blockLenBytes), libStr = new Uint8Array(2);
    libStr[0] = (numBytes >> 8) & 0xff;
    libStr[1] = numBytes & 0xff;
    const b0Input = joinAll$1([zPad, msg, libStr, new Uint8Array([0]), dstPrime]), b0 = new Uint8Array(await crypto.subtle.digest(hash, b0Input)), b1Input = joinAll$1([b0, new Uint8Array([1]), dstPrime]);
    let bi = new Uint8Array(await crypto.subtle.digest(hash, b1Input)), pseudo = joinAll$1([bi]);
    for (let i = 2; i <= ell; i++) {
        const biInput = joinAll$1([xor$1(bi, b0), new Uint8Array([i]), dstPrime]);
        bi = new Uint8Array(await crypto.subtle.digest(hash, biInput)); // eslint-disable-line no-await-in-loop
        pseudo = joinAll$1([pseudo, bi]);
    }
    return pseudo.slice(0, numBytes);
}
var GroupID;
(function (GroupID) {
    GroupID["P256"] = "P-256";
    GroupID["P384"] = "P-384";
    GroupID["P521"] = "P-521";
})(GroupID || (GroupID = {}));
/* eslint new-cap: ["error", { "properties": false }] */
class Group {
    constructor(gid) {
        switch (gid) {
            case GroupID.P256:
                this.curve = sjcl.ecc.curves.c256;
                this.size = 32;
                this.hashParams = {
                    hash: 'SHA-256',
                    L: 48,
                    Z: -10,
                    c2: '0x78bc71a02d89ec07214623f6d0f955072c7cc05604a5a6e23ffbf67115fa5301'
                };
                break;
            case GroupID.P384:
                this.curve = sjcl.ecc.curves.c384;
                this.size = 48;
                this.hashParams = {
                    hash: 'SHA-384',
                    L: 72,
                    Z: -12,
                    c2: '0x19877cc1041b7555743c0ae2e3a3e61fb2aaa2e0e87ea557a563d8b598a0940d0a697a9e0b9e92cfaa314f583c9d066'
                };
                break;
            case GroupID.P521:
                this.curve = sjcl.ecc.curves.c521;
                this.size = 66;
                this.hashParams = {
                    hash: 'SHA-512',
                    L: 98,
                    Z: -4,
                    c2: '0x8'
                };
                break;
            default:
                throw new Error(`group not implemented: ${gid}`);
        }
        this.id = gid;
    }
    static getID(id) {
        switch (id) {
            case 'P-256':
                return GroupID.P256;
            case 'P-384':
                return GroupID.P384;
            case 'P-521':
                return GroupID.P521;
            default:
                throw new Error(`group not implemented: ${id}`);
        }
    }
    identity() {
        return new sjcl.ecc.point(this.curve);
    }
    generator() {
        return this.curve.G;
    }
    order() {
        return this.curve.r;
    }
    // Serializes an element in uncompressed form.
    serUnComp(e) {
        const xy = sjcl.codec.arrayBuffer.fromBits(e.toBits(), false), bytes = new Uint8Array(xy);
        if (bytes.length !== 2 * this.size) {
            throw new Error('error serializing element');
        }
        const serElt = new SerializedElt(1 + 2 * this.size);
        serElt[0] = 0x04;
        serElt.set(bytes, 1);
        return serElt;
    }
    // Serializes an element in compressed form.
    serComp(e) {
        const x = sjcl.codec.arrayBuffer.fromBits(e.x.toBits(), false), bytes = new Uint8Array(x), serElt = new SerializedElt(1 + this.size);
        serElt[0] = 0x02 | (e.y.limbs[0] & 1);
        serElt.set(bytes, 1 + this.size - bytes.length);
        return serElt;
    }
    serialize(e, compressed = true) {
        if (e.isIdentity) {
            return new SerializedElt(1);
        }
        e.x.fullReduce();
        e.y.fullReduce();
        return compressed ? this.serComp(e) : this.serUnComp(e);
    }
    // Deserializes an element in compressed form.
    deserComp(serElt) {
        const array = Array.from(serElt.slice(1)), bytes = sjcl.codec.bytes.toBits(array), x = new this.curve.field(sjcl.bn.fromBits(bytes)), p = this.curve.field.modulus, exp = p.add(new sjcl.bn(1)).halveM().halveM();
        let y = x.square().add(this.curve.a).mul(x).add(this.curve.b).power(exp);
        y.fullReduce();
        if ((serElt[0] & 1) !== (y.limbs[0] & 1)) {
            y = p.sub(y).mod(p);
        }
        const point = new sjcl.ecc.point(this.curve, new sjcl.bn(x), new sjcl.bn(y));
        if (!point.isValid()) {
            throw new Error('point not in curve');
        }
        return point;
    }
    // Deserializes an element in uncompressed form.
    deserUnComp(serElt) {
        const array = Array.from(serElt.slice(1)), b = sjcl.codec.bytes.toBits(array), point = this.curve.fromBits(b);
        point.x.fullReduce();
        point.y.fullReduce();
        return point;
    }
    // Deserializes an element, handles both compressed and uncompressed forms.
    deserialize(serElt) {
        const len = serElt.length;
        switch (true) {
            case len === 1 && serElt[0] === 0x00:
                return this.identity();
            case len === 1 + this.size && (serElt[0] === 0x02 || serElt[0] === 0x03):
                return this.deserComp(serElt);
            case len === 1 + 2 * this.size && serElt[0] === 0x04:
                return this.deserUnComp(serElt);
            default:
                throw new Error('error deserializing element');
        }
    }
    serializeScalar(s) {
        const k = s.mod(this.curve.r);
        k.normalize();
        const ab = sjcl.codec.arrayBuffer.fromBits(k.toBits(), false), unpaded = new Uint8Array(ab), serScalar = new SerializedScalar(this.size);
        serScalar.set(unpaded, this.size - unpaded.length);
        return serScalar;
    }
    deserializeScalar(serScalar) {
        const array = Array.from(serScalar), k = sjcl.bn.fromBits(sjcl.codec.bytes.toBits(array));
        k.normalize();
        if (k.greaterEquals(this.curve.r)) {
            throw new Error('error deserializing scalar');
        }
        return k;
    }
    addScalar(a, b) {
        const c = a.add(b);
        c.mod(this.curve.r);
        c.normalize();
        return c;
    }
    invScalar(k) {
        return k.inverseMod(this.curve.r);
    }
    static mul(k, e) {
        return e.mult(k);
    }
    mulBase(k) {
        return this.curve.G.mult(k);
    }
    equal(a, b) {
        if (this.curve !== a.curve || this.curve !== b.curve) {
            return false;
        }
        if (a.isIdentity && b.isIdentity) {
            return true;
        }
        return a.x.equals(b.x) && a.y.equals(b.y);
    }
    randomScalar() {
        const msg = new Uint8Array(this.hashParams.L);
        crypto.getRandomValues(msg);
        return this.hashToScalar(msg, new Uint8Array());
    }
    async hashToScalar(msg, dst) {
        const { hash, L } = this.hashParams, bytes = await expandXMD(hash, msg, dst, L), array = Array.from(bytes), bitArr = sjcl.codec.bytes.toBits(array), s = sjcl.bn.fromBits(bitArr).mod(this.curve.r);
        return s;
    }
    async hashToGroup(msg, dst) {
        const u = await this.hashToField(msg, dst, 2), Q0 = this.sswu(u[0]), Q1 = this.sswu(u[1]);
        return Q0.toJac().add(Q1).toAffine();
    }
    async hashToField(msg, dst, count) {
        const { hash, L } = this.hashParams, bytes = await expandXMD(hash, msg, dst, count * L), u = new Array(count);
        for (let i = 0; i < count; i++) {
            const j = i * L, array = Array.from(bytes.slice(j, j + L)), bitArr = sjcl.codec.bytes.toBits(array);
            u[i] = new this.curve.field(sjcl.bn.fromBits(bitArr));
        }
        return u;
    }
    sswu(u) {
        const A = this.curve.a, B = this.curve.b, p = this.curve.field.modulus, Z = new this.curve.field(this.hashParams.Z), c2 = new sjcl.bn(this.hashParams.c2), c1 = p.sub(new sjcl.bn(3)).halveM().halveM(), // c1 = (p-3)/4
        zero = new this.curve.field(0), one = new this.curve.field(1);
        function sgn(x) {
            x.fullReduce();
            return x.limbs[0] & 1;
        }
        function cmov(x, y, b) {
            return b ? y : x;
        }
        let tv1 = u.square(); //          1. tv1 = u^2
        const tv3 = Z.mul(tv1); //        2. tv3 = Z * tv1
        let tv2 = tv3.square(), //       3. tv2 = tv3^2
        xd = tv2.add(tv3), //        4.  xd = tv2 + tv3
        x1n = xd.add(one); //         5. x1n = xd + 1
        x1n = x1n.mul(B); //              6. x1n = x1n * B
        let tv4 = p.sub(A);
        xd = xd.mul(tv4); //              7.  xd = -A * xd
        const e1 = xd.equals(zero); //    8.  e1 = xd == 0
        tv4 = A.mul(Z);
        xd = cmov(xd, tv4, e1); //        9.  xd = CMOV(xd, Z * A, e1)
        tv2 = xd.square(); //            10. tv2 = xd^2
        const gxd = tv2.mul(xd); //      11. gxd = tv2 * xd
        tv2 = tv2.mul(A); //             12. tv2 = A * tv2
        let gx1 = x1n.square(); //       13. gx1 = x1n^2
        gx1 = gx1.add(tv2); //           14. gx1 = gx1 + tv2
        gx1 = gx1.mul(x1n); //           15. gx1 = gx1 * x1n
        tv2 = gxd.mul(B); //             16. tv2 = B * gxd
        gx1 = gx1.add(tv2); //           17. gx1 = gx1 + tv2
        tv4 = gxd.square(); //           18. tv4 = gxd^2
        tv2 = gx1.mul(gxd); //           19. tv2 = gx1 * gxd
        tv4 = tv4.mul(tv2); //           20. tv4 = tv4 * tv2
        let y1 = tv4.power(c1); //       21.  y1 = tv4^c1
        y1 = y1.mul(tv2); //             22.  y1 = y1 * tv2
        const x2n = tv3.mul(x1n); //     23. x2n = tv3 * x1n
        let y2 = y1.mul(c2); //          24.  y2 = y1 * c2
        y2 = y2.mul(tv1); //             25.  y2 = y2 * tv1
        y2 = y2.mul(u); //               26.  y2 = y2 * u
        tv2 = y1.square(); //            27. tv2 = y1^2
        tv2 = tv2.mul(gxd); //           28. tv2 = tv2 * gxd
        const e2 = tv2.equals(gx1), //  29.  e2 = tv2 == gx1
        xn = cmov(x2n, x1n, e2); //  30.  xn = CMOV(x2n, x1n, e2)
        let y = cmov(y2, y1, e2); //     31.   y = CMOV(y2, y1, e2)
        const e3 = sgn(u) === sgn(y); // 32.  e3 = sgn0(u) == sgn0(y)
        tv1 = p.sub(y);
        y = cmov(tv1, y, e3); //         33.   y = CMOV(-y, y, e3)
        let x = xd.inverseMod(p); //     34. return (xn, xd, y, 1)
        x = xn.mul(x);
        const point = new sjcl.ecc.point(this.curve, new sjcl.bn(x), new sjcl.bn(y));
        if (!point.isValid()) {
            throw new Error('point not in curve');
        }
        return point;
    }
}
Group.paranoia = 6;

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
class Blind extends SerializedScalar {
    constructor() {
        super(...arguments);
        this._BlindBrand = '';
    }
}
class Blinded extends SerializedElt {
    constructor() {
        super(...arguments);
        this._BlindedBrand = '';
    }
}
class Evaluation extends SerializedElt {
    constructor() {
        super(...arguments);
        this._EvaluationBrand = '';
    }
}
var OprfID;
(function (OprfID) {
    OprfID[OprfID["OPRF_P256_SHA256"] = 3] = "OPRF_P256_SHA256";
    OprfID[OprfID["OPRF_P384_SHA384"] = 4] = "OPRF_P384_SHA384";
    OprfID[OprfID["OPRF_P521_SHA512"] = 5] = "OPRF_P521_SHA512";
})(OprfID || (OprfID = {}));
class Oprf {
    constructor(id) {
        this.params = Oprf.params(id);
    }
    static validateID(id) {
        switch (id) {
            case OprfID.OPRF_P256_SHA256:
            case OprfID.OPRF_P384_SHA384:
            case OprfID.OPRF_P521_SHA512:
                return true;
            default:
                throw new Error(`not supported ID: ${id}`);
        }
    }
    static params(id) {
        Oprf.validateID(id);
        let gid = GroupID.P256, hash = 'SHA-256';
        switch (id) {
            case OprfID.OPRF_P256_SHA256:
                break;
            case OprfID.OPRF_P384_SHA384:
                gid = GroupID.P384;
                hash = 'SHA-384';
                break;
            case OprfID.OPRF_P521_SHA512:
                gid = GroupID.P521;
                hash = 'SHA-512';
                break;
            default:
                throw new Error(`not supported ID: ${id}`);
        }
        const gg = new Group(gid);
        return {
            id,
            gg,
            hash,
            blindedSize: 1 + gg.size,
            evaluationSize: 1 + gg.size,
            blindSize: gg.size
        };
    }
    static getContextString(id) {
        Oprf.validateID(id);
        return joinAll$1([new TextEncoder().encode(Oprf.version), new Uint8Array([Oprf.mode, 0, id])]);
    }
    static getHashToGroupDST(id) {
        return joinAll$1([new TextEncoder().encode('HashToGroup-'), Oprf.getContextString(id)]);
    }
    static getHashToScalarDST(id) {
        return joinAll$1([new TextEncoder().encode('HashToScalar-'), Oprf.getContextString(id)]);
    }
    static getEvalContext(id, info) {
        return joinAll$1([
            new TextEncoder().encode('Context-'),
            Oprf.getContextString(id),
            to16bits(info.length),
            info
        ]);
    }
    async coreFinalize(input, info, unblindedElement) {
        const finalizeDST = joinAll$1([
            new TextEncoder().encode('Finalize-'),
            Oprf.getContextString(this.params.id)
        ]), hashInput = joinAll$1([
            to16bits(input.length),
            input,
            to16bits(info.length),
            info,
            to16bits(unblindedElement.length),
            unblindedElement,
            to16bits(finalizeDST.length),
            finalizeDST
        ]);
        return new Uint8Array(await crypto.subtle.digest(this.params.hash, hashInput));
    }
}
Oprf.mode = 0;
Oprf.version = 'VOPRF08-';

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
class OPRFClient extends Oprf {
    async randomBlinder() {
        const scalar = await this.params.gg.randomScalar(), blind = new Blind(this.params.gg.serializeScalar(scalar));
        return { scalar, blind };
    }
    async blind(input) {
        const { scalar, blind } = await this.randomBlinder(), dst = Oprf.getHashToGroupDST(this.params.id), P = await this.params.gg.hashToGroup(input, dst), Q = Group.mul(scalar, P), blindedElement = new Blinded(this.params.gg.serialize(Q));
        return { blind, blindedElement };
    }
    finalize(input, info, blind, evaluation) {
        const blindScalar = this.params.gg.deserializeScalar(blind), blindScalarInv = this.params.gg.invScalar(blindScalar), Z = this.params.gg.deserialize(evaluation), N = Group.mul(blindScalarInv, Z), unblinded = this.params.gg.serialize(N);
        return this.coreFinalize(input, info, unblinded);
    }
}

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
class OPRFServer extends Oprf {
    constructor(id, privateKey) {
        super(id);
        this.supportsWebCryptoOPRF = false;
        this.privateKey = privateKey;
    }
    async evaluate(blindedElement, info) {
        const context = Oprf.getEvalContext(this.params.id, info), dst = Oprf.getHashToScalarDST(this.params.id), m = await this.params.gg.hashToScalar(context, dst), serSk = new SerializedScalar(this.privateKey), sk = this.params.gg.deserializeScalar(serSk), t = this.params.gg.addScalar(sk, m), tInv = this.params.gg.invScalar(t);
        if (this.supportsWebCryptoOPRF) {
            const serTInv = this.params.gg.serializeScalar(tInv);
            return this.evaluateWebCrypto(blindedElement, serTInv);
        }
        return Promise.resolve(this.evaluateSJCL(blindedElement, tInv));
    }
    async evaluateWebCrypto(blindedElement, secret) {
        const key = await crypto.subtle.importKey('raw', secret, {
            name: 'OPRF',
            namedCurve: this.params.gg.id
        }, true, ['sign']);
        // webcrypto accepts only compressed points.
        let compressed = Uint8Array.from(blindedElement);
        if (blindedElement[0] === 0x04) {
            const P = this.params.gg.deserialize(blindedElement);
            compressed = Uint8Array.from(this.params.gg.serialize(P, true));
        }
        const evaluation = await crypto.subtle.sign('OPRF', key, compressed);
        return new Evaluation(evaluation);
    }
    evaluateSJCL(blindedElement, secret) {
        const P = this.params.gg.deserialize(blindedElement), Z = Group.mul(secret, P);
        return new Evaluation(this.params.gg.serialize(Z));
    }
    async fullEvaluate(input, info) {
        const dst = Oprf.getHashToGroupDST(this.params.id), T = await this.params.gg.hashToGroup(input, dst), issuedElement = new Blinded(this.params.gg.serialize(T)), evaluation = await this.evaluate(issuedElement, info), digest = await this.coreFinalize(input, info, evaluation);
        return digest;
    }
    async verifyFinalize(input, output, info) {
        const digest = await this.fullEvaluate(input, info);
        return ctEqual$1(output, digest);
    }
}

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
function getKeySizes(id) {
    const { gg } = Oprf.params(id);
    return { Nsk: gg.size, Npk: 1 + gg.size };
}
async function randomPrivateKey(id) {
    const { gg } = Oprf.params(id), priv = await gg.randomScalar();
    return new Uint8Array(gg.serializeScalar(priv));
}
function generatePublicKey(id, privateKey) {
    const { gg } = Oprf.params(id), priv = gg.deserializeScalar(new SerializedScalar(privateKey)), pub = gg.mulBase(priv);
    return new Uint8Array(gg.serialize(pub));
}

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
// Copyright (c) 2021 Cloudflare, Inc.
// Licensed under the BSD-3-Clause license found in the LICENSE file or
// at https://opensource.org/licenses/BSD-3-Clause
function joinAll(a) {
    let size = 0;
    for (let i = 0; i < a.length; i++) {
        size += a[i].length;
    }
    const ret = new Uint8Array(new ArrayBuffer(size));
    for (let i = 0, offset = 0; i < a.length; i++) {
        ret.set(a[i], offset);
        offset += a[i].length;
    }
    return ret;
}
function encode_number(n, bits) {
    if (!(bits > 0 && bits <= 32)) {
        throw new Error('only supports 32-bit encoding');
    }
    const max = 1 << bits;
    if (!(n >= 0 && n < max)) {
        throw new Error(`number out of range [0,2^${bits}-1]`);
    }
    const numBytes = Math.ceil(bits / 8);
    const out = new Uint8Array(numBytes);
    for (let i = 0; i < numBytes; i++) {
        out[(numBytes - 1 - i)] = (n >> (8 * i)) & 0xff;
    }
    return out;
}
function decode_number(a, bits) {
    if (!(bits > 0 && bits <= 32)) {
        throw new Error('only supports 32-bit encoding');
    }
    const numBytes = Math.ceil(bits / 8);
    if (a.length !== numBytes) {
        throw new Error('array has wrong size');
    }
    let out = 0;
    for (let i = 0; i < a.length; i++) {
        out <<= 8;
        out += a[i];
    }
    return out;
}
function encode_vector(a, bits_header) {
    return joinAll([encode_number(a.length, bits_header), a]);
}
function decode_vector(a, bits_header) {
    if (a.length === 0) {
        throw new Error('empty vector not allowed');
    }
    const numBytes = Math.ceil(bits_header / 8);
    const header = a.subarray(0, numBytes);
    const len = decode_number(header, bits_header);
    const consumed = numBytes + len;
    const payload = a.slice(numBytes, consumed);
    return { payload, consumed };
}
function encode_vector_8(a) {
    return encode_vector(a, 8);
}
function encode_vector_16(a) {
    return encode_vector(a, 16);
}
function decode_vector_16(a) {
    return decode_vector(a, 16);
}
function checked_vector(a, n, str = 'array') {
    if (a.length < n) {
        throw new Error(`${str} has wrong length`);
    }
    return a.slice(0, n);
}
function xor(a, b) {
    if (a.length !== b.length || a.length === 0) {
        throw new Error('arrays of different length');
    }
    const n = a.length;
    const c = new Uint8Array(n);
    for (let i = 0; i < n; i++) {
        c[i] = a[i] ^ b[i];
    }
    return c;
}
function ctEqual(a, b) {
    if (a.length !== b.length || a.length === 0) {
        throw new Error('arrays of different length');
    }
    const n = a.length;
    let c = 0;
    for (let i = 0; i < n; i++) {
        c |= a[i] ^ b[i];
    }
    return c === 0;
}

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
const te = new TextEncoder();
function encStr(s) {
    return Array.from(te.encode(s));
}
const LABELS = {
    AuthKey: encStr('AuthKey'),
    ClientMAC: encStr('ClientMAC'),
    CredentialResponsePad: encStr('CredentialResponsePad'),
    ExportKey: encStr('ExportKey'),
    HandshakeSecret: encStr('HandshakeSecret'),
    MaskingKey: encStr('MaskingKey'),
    OPAQUE: encStr('OPAQUE-'),
    OPAQUE_DeriveAuthKeyPair: encStr('OPAQUE-DeriveAuthKeyPair'),
    OPAQUE_DeriveKeyPair: encStr('OPAQUE-DeriveKeyPair'),
    OprfKey: encStr('OprfKey'),
    PrivateKey: encStr('PrivateKey'),
    RFC: encStr('RFCXXXX'),
    ServerMAC: encStr('ServerMAC'),
    SessionKey: encStr('SessionKey')
};
class OPRFBaseMode {
    constructor(id) {
        this.id = id;
        const { blindedSize, hash } = Oprf.params(id);
        this.Noe = blindedSize;
        this.hash = hash;
        this.name = OprfID[id];
    }
    async blind(input) {
        const res = await new OPRFClient(this.id).blind(input);
        return {
            blind: new Uint8Array(res.blind.buffer),
            blindedElement: new Uint8Array(res.blindedElement.buffer)
        };
    }
    async evaluate(key, blinded) {
        const res = await new OPRFServer(this.id, key).evaluate(new Blinded(blinded), new Uint8Array());
        return new Uint8Array(res.buffer);
    }
    finalize(input, blind, evaluation) {
        return new OPRFClient(this.id).finalize(input, new Uint8Array(), new Blind(blind), new Evaluation(evaluation));
    }
    async deriveOPRFKey(seed) {
        const { gg } = Oprf.params(this.id);
        const priv = await gg.hashToScalar(seed, Uint8Array.from(LABELS.OPAQUE_DeriveKeyPair));
        return new Uint8Array(gg.serializeScalar(priv));
    }
}
function expandLabel(cfg, secret, label, context, length) {
    const customLabel = joinAll([
        encode_number(length, 16),
        encode_vector_8(joinAll([Uint8Array.from(LABELS.OPAQUE), label])),
        encode_vector_8(context)
    ]);
    return cfg.kdf.expand(secret, customLabel, length);
}
function deriveSecret(cfg, secret, label, transHash) {
    return expandLabel(cfg, secret, label, transHash, cfg.kdf.Nx);
}
function preambleBuild(ke1, ke2, server_identity, client_identity, context) {
    return joinAll([
        Uint8Array.from(LABELS.RFC),
        encode_vector_16(context),
        encode_vector_16(client_identity),
        Uint8Array.from(ke1.serialize()),
        encode_vector_16(server_identity),
        Uint8Array.from(ke2.response.serialize()),
        ke2.auth_response.server_nonce,
        ke2.auth_response.server_keyshare
    ]);
}
function tripleDH_IKM(cfg, keys) {
    const { gg } = Oprf.params(cfg.oprf.id);
    const ikm = new Array(3);
    for (let i = 0; i < 3; i++) {
        const { sk, pk } = keys[i];
        const point = gg.deserialize(new SerializedElt(pk));
        const scalar = gg.deserializeScalar(new SerializedScalar(sk));
        const p = Group.mul(scalar, point);
        ikm[i] = gg.serialize(p);
    }
    return joinAll(ikm);
}
async function deriveKeys(cfg, ikm, preamble) {
    const nosalt = new Uint8Array(cfg.hash.Nh);
    const prk = await cfg.kdf.extract(nosalt, ikm);
    const h_preamble = await cfg.hash.sum(preamble);
    const handshake_secret = await deriveSecret(cfg, prk, Uint8Array.from(LABELS.HandshakeSecret), h_preamble);
    const session_key = await deriveSecret(cfg, prk, Uint8Array.from(LABELS.SessionKey), h_preamble);
    const no_transcript = new Uint8Array();
    const Km2 = await deriveSecret(cfg, handshake_secret, Uint8Array.from(LABELS.ServerMAC), no_transcript);
    const Km3 = await deriveSecret(cfg, handshake_secret, Uint8Array.from(LABELS.ClientMAC), no_transcript);
    return { Km2, Km3, session_key };
}
class AKE3DH {
    constructor(oprfID) {
        this.oprfID = oprfID;
        const { Npk, Nsk } = getKeySizes(oprfID);
        this.Npk = Npk;
        this.Nsk = Nsk;
    }
    async deriveAuthKeyPair(seed) {
        const { gg } = Oprf.params(this.oprfID);
        const priv = await gg.hashToScalar(seed, Uint8Array.from(LABELS.OPAQUE_DeriveAuthKeyPair));
        const private_key = new Uint8Array(gg.serializeScalar(priv));
        const public_key = generatePublicKey(this.oprfID, private_key);
        return { private_key, public_key };
    }
    recoverPublicKey(private_key) {
        const public_key = generatePublicKey(this.oprfID, private_key);
        return { private_key, public_key };
    }
    async generateAuthKeyPair() {
        const keypair = this.recoverPublicKey(await randomPrivateKey(this.oprfID));
        return {
            private_key: Array.from(keypair.private_key),
            public_key: Array.from(keypair.public_key)
        };
    }
}

/*! noble-hashes - MIT License (c) 2021 Paul Miller (paulmillr.com) */
const u32 = (arr) => new Uint32Array(arr.buffer, arr.byteOffset, Math.floor(arr.byteLength / 4));
// Cast array to view
const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
// The rotate right (circular right shift) operation for uint32
const rotr = (word, shift) => (word << (32 - shift)) | (word >>> shift);
const isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
// There is almost no big endian hardware, but js typed arrays uses platform specific endianess.
// So, just to be sure not to corrupt anything.
if (!isLE)
    throw new Error('Non little-endian hardware is not supported');
Array.from({ length: 256 }, (v, i) => i.toString(16).padStart(2, '0'));
// Currently avoid insertion of polyfills with packers (browserify/webpack/etc)
// But setTimeout is pretty slow, maybe worth to investigate howto do minimal polyfill here
(() => {
    const nodeRequire = typeof module !== 'undefined' &&
        typeof module.require === 'function' &&
        module.require.bind(module);
    try {
        if (nodeRequire) {
            const { setImmediate } = nodeRequire('timers');
            return () => new Promise((resolve) => setImmediate(resolve));
        }
    }
    catch (e) { }
    return () => new Promise((resolve) => setTimeout(resolve, 0));
})();
function toBytes(data) {
    if (typeof data === 'string')
        data = new TextEncoder().encode(data);
    if (!(data instanceof Uint8Array))
        throw new TypeError(`Expected input type is Uint8Array (got ${typeof data})`);
    return data;
}
function assertNumber(n) {
    if (!Number.isSafeInteger(n))
        throw new Error(`Wrong integer: ${n}`);
}
function assertHash(hash) {
    if (typeof hash !== 'function' || typeof hash.init !== 'function')
        throw new Error('Hash should be wrapped by utils.wrapConstructor');
    assertNumber(hash.outputLen);
    assertNumber(hash.blockLen);
}
// For runtime check if class implements interface
class Hash$1 {
    // Safe version that clones internal state
    clone() {
        return this._cloneInto();
    }
}
// Check if object doens't have custom constructor (like Uint8Array/Array)
const isPlainObject = (obj) => Object.prototype.toString.call(obj) === '[object Object]' && obj.constructor === Object;
function checkOpts(def, _opts) {
    if (_opts !== undefined && (typeof _opts !== 'object' || !isPlainObject(_opts)))
        throw new TypeError('Options should be object or undefined');
    const opts = Object.assign(def, _opts);
    return opts;
}
function wrapConstructor(hashConstructor) {
    const hashC = (message) => hashConstructor().update(toBytes(message)).digest();
    const tmp = hashConstructor();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashConstructor();
    hashC.init = hashC.create;
    return hashC;
}

// Polyfill for Safari 14
function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
// Base SHA2 class (RFC 6234)
class SHA2 extends Hash$1 {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.buffer = new Uint8Array(blockLen);
        this.view = createView(this.buffer);
    }
    update(data) {
        if (this.destroyed)
            throw new Error('instance is destroyed');
        const { view, buffer, blockLen, finished } = this;
        if (finished)
            throw new Error('digest() was already called');
        data = toBytes(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = createView(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        if (this.destroyed)
            throw new Error('instance is destroyed');
        if (!(out instanceof Uint8Array) || out.length < this.outputLen)
            throw new Error('_Sha2: Invalid output buffer');
        if (this.finished)
            throw new Error('digest() was already called');
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        this.buffer.subarray(pos).fill(0);
        // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // NOTE: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64bit of that value.
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = createView(out);
        this.get().forEach((v, i) => oview.setUint32(4 * i, v, isLE));
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.length = length;
        to.pos = pos;
        to.finished = finished;
        to.destroyed = destroyed;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
}

// Choice: a ? b : c
const Chi = (a, b, c) => (a & b) ^ (~a & c);
// Majority function, true if any two inpust is true
const Maj = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
// Round constants:
// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
// prettier-ignore
const SHA256_K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
// Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
// prettier-ignore
const IV = new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);
// Temporary buffer, not used to store anything between runs
// Named this way because it matches specification.
const SHA256_W = new Uint32Array(64);
class SHA256 extends SHA2 {
    constructor() {
        super(64, 32, 8, false);
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        this.A = IV[0] | 0;
        this.B = IV[1] | 0;
        this.C = IV[2] | 0;
        this.D = IV[3] | 0;
        this.E = IV[4] | 0;
        this.F = IV[5] | 0;
        this.G = IV[6] | 0;
        this.H = IV[7] | 0;
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3);
            const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10);
            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
            const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
            const T2 = (sigma0 + Maj(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        SHA256_W.fill(0);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        this.buffer.fill(0);
    }
}
const sha256 = wrapConstructor(() => new SHA256());

// HMAC (RFC 2104)
class HMAC extends Hash$1 {
    constructor(hash, _key) {
        super();
        this.finished = false;
        this.destroyed = false;
        assertHash(hash);
        const key = toBytes(_key);
        this.iHash = hash.create();
        if (!(this.iHash instanceof Hash$1))
            throw new TypeError('Expected instance of class which extends utils.Hash');
        const blockLen = (this.blockLen = this.iHash.blockLen);
        this.outputLen = this.iHash.outputLen;
        const pad = new Uint8Array(blockLen);
        // blockLen can be bigger than outputLen
        pad.set(key.length > this.iHash.blockLen ? hash.create().update(key).digest() : key);
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36;
        this.iHash.update(pad);
        // By doing update (processing of first block) of outer hash here we can re-use it between multiple calls via clone
        this.oHash = hash.create();
        // Undo internal XOR && apply outer XOR
        for (let i = 0; i < pad.length; i++)
            pad[i] ^= 0x36 ^ 0x5c;
        this.oHash.update(pad);
        pad.fill(0);
    }
    update(buf) {
        if (this.destroyed)
            throw new Error('instance is destroyed');
        this.iHash.update(buf);
        return this;
    }
    digestInto(out) {
        if (this.destroyed)
            throw new Error('instance is destroyed');
        if (!(out instanceof Uint8Array) || out.length !== this.outputLen)
            throw new Error('HMAC: Invalid output buffer');
        if (this.finished)
            throw new Error('digest() was already called');
        this.finished = true;
        this.iHash.digestInto(out);
        this.oHash.update(out);
        this.oHash.digestInto(out);
        this.destroy();
    }
    digest() {
        const out = new Uint8Array(this.oHash.outputLen);
        this.digestInto(out);
        return out;
    }
    _cloneInto(to) {
        // Create new instance without calling constructor since key already in state and we don't know it.
        to || (to = Object.create(Object.getPrototypeOf(this), {}));
        const { oHash, iHash, finished, destroyed, blockLen, outputLen } = this;
        to = to;
        to.finished = finished;
        to.destroyed = destroyed;
        to.blockLen = blockLen;
        to.outputLen = outputLen;
        to.oHash = oHash._cloneInto(to.oHash);
        to.iHash = iHash._cloneInto(to.iHash);
        return to;
    }
    destroy() {
        this.destroyed = true;
        this.oHash.destroy();
        this.iHash.destroy();
    }
}
const hmac = (hash, key, message) => new HMAC(hash, key).update(message).digest();
hmac.create = (hash, key) => new HMAC(hash, key);
hmac.init = hmac.create;

// Common prologue and epilogue for sync/async functions
function pbkdf2Init(hash, _password, _salt, _opts) {
    assertHash(hash);
    const opts = checkOpts({ dkLen: 32, asyncTick: 10 }, _opts);
    const { c, dkLen, asyncTick } = opts;
    assertNumber(c);
    assertNumber(dkLen);
    assertNumber(asyncTick);
    if (c < 1)
        throw new Error('PBKDF2: iterations (c) should be >= 1');
    const password = toBytes(_password);
    const salt = toBytes(_salt);
    // DK = PBKDF2(PRF, Password, Salt, c, dkLen);
    const DK = new Uint8Array(dkLen);
    // U1 = PRF(Password, Salt + INT_32_BE(i))
    const PRF = hmac.init(hash, password);
    const PRFSalt = PRF._cloneInto().update(salt);
    return { c, dkLen, asyncTick, DK, PRF, PRFSalt };
}
function pbkdf2Output(PRF, PRFSalt, DK, prfW, u) {
    PRF.destroy();
    PRFSalt.destroy();
    if (prfW)
        prfW.destroy();
    u.fill(0);
    return DK;
}
function pbkdf2(hash, password, salt, _opts) {
    const { c, dkLen, DK, PRF, PRFSalt } = pbkdf2Init(hash, password, salt, _opts);
    let prfW; // Working copy
    const arr = new Uint8Array(4);
    const view = createView(arr);
    const u = new Uint8Array(PRF.outputLen);
    // DK = T1 + T2 + ⋯ + Tdklen/hlen
    for (let ti = 1, pos = 0; pos < dkLen; ti++, pos += PRF.outputLen) {
        // Ti = F(Password, Salt, c, i)
        const Ti = DK.subarray(pos, pos + PRF.outputLen);
        view.setInt32(0, ti, false);
        // F(Password, Salt, c, i) = U1 ^ U2 ^ ⋯ ^ Uc
        // U1 = PRF(Password, Salt + INT_32_BE(i))
        (prfW = PRFSalt._cloneInto(prfW)).update(arr).digestInto(u);
        Ti.set(u.subarray(0, Ti.length));
        for (let ui = 1; ui < c; ui++) {
            // Uc = PRF(Password, Uc−1)
            PRF._cloneInto(prfW).update(u).digestInto(u);
            for (let i = 0; i < Ti.length; i++)
                Ti[i] ^= u[i];
        }
    }
    return pbkdf2Output(PRF, PRFSalt, DK, prfW, u);
}

// Left rotate for uint32
const rotl = (a, b) => (a << b) | (a >>> (32 - b));
// prettier-ignore
function XorAndSalsa(prev, pi, input, ii, out, oi) {
    // Based on https://cr.yp.to/salsa20.html
    // Xor blocks
    let y00 = prev[pi++] ^ input[ii++], y01 = prev[pi++] ^ input[ii++];
    let y02 = prev[pi++] ^ input[ii++], y03 = prev[pi++] ^ input[ii++];
    let y04 = prev[pi++] ^ input[ii++], y05 = prev[pi++] ^ input[ii++];
    let y06 = prev[pi++] ^ input[ii++], y07 = prev[pi++] ^ input[ii++];
    let y08 = prev[pi++] ^ input[ii++], y09 = prev[pi++] ^ input[ii++];
    let y10 = prev[pi++] ^ input[ii++], y11 = prev[pi++] ^ input[ii++];
    let y12 = prev[pi++] ^ input[ii++], y13 = prev[pi++] ^ input[ii++];
    let y14 = prev[pi++] ^ input[ii++], y15 = prev[pi++] ^ input[ii++];
    // Save state to temporary variables (salsa)
    let x00 = y00, x01 = y01, x02 = y02, x03 = y03, x04 = y04, x05 = y05, x06 = y06, x07 = y07, x08 = y08, x09 = y09, x10 = y10, x11 = y11, x12 = y12, x13 = y13, x14 = y14, x15 = y15;
    // Main loop (salsa)
    for (let i = 0; i < 8; i += 2) {
        x04 ^= rotl(x00 + x12 | 0, 7);
        x08 ^= rotl(x04 + x00 | 0, 9);
        x12 ^= rotl(x08 + x04 | 0, 13);
        x00 ^= rotl(x12 + x08 | 0, 18);
        x09 ^= rotl(x05 + x01 | 0, 7);
        x13 ^= rotl(x09 + x05 | 0, 9);
        x01 ^= rotl(x13 + x09 | 0, 13);
        x05 ^= rotl(x01 + x13 | 0, 18);
        x14 ^= rotl(x10 + x06 | 0, 7);
        x02 ^= rotl(x14 + x10 | 0, 9);
        x06 ^= rotl(x02 + x14 | 0, 13);
        x10 ^= rotl(x06 + x02 | 0, 18);
        x03 ^= rotl(x15 + x11 | 0, 7);
        x07 ^= rotl(x03 + x15 | 0, 9);
        x11 ^= rotl(x07 + x03 | 0, 13);
        x15 ^= rotl(x11 + x07 | 0, 18);
        x01 ^= rotl(x00 + x03 | 0, 7);
        x02 ^= rotl(x01 + x00 | 0, 9);
        x03 ^= rotl(x02 + x01 | 0, 13);
        x00 ^= rotl(x03 + x02 | 0, 18);
        x06 ^= rotl(x05 + x04 | 0, 7);
        x07 ^= rotl(x06 + x05 | 0, 9);
        x04 ^= rotl(x07 + x06 | 0, 13);
        x05 ^= rotl(x04 + x07 | 0, 18);
        x11 ^= rotl(x10 + x09 | 0, 7);
        x08 ^= rotl(x11 + x10 | 0, 9);
        x09 ^= rotl(x08 + x11 | 0, 13);
        x10 ^= rotl(x09 + x08 | 0, 18);
        x12 ^= rotl(x15 + x14 | 0, 7);
        x13 ^= rotl(x12 + x15 | 0, 9);
        x14 ^= rotl(x13 + x12 | 0, 13);
        x15 ^= rotl(x14 + x13 | 0, 18);
    }
    // Write output (salsa)
    out[oi++] = (y00 + x00) | 0;
    out[oi++] = (y01 + x01) | 0;
    out[oi++] = (y02 + x02) | 0;
    out[oi++] = (y03 + x03) | 0;
    out[oi++] = (y04 + x04) | 0;
    out[oi++] = (y05 + x05) | 0;
    out[oi++] = (y06 + x06) | 0;
    out[oi++] = (y07 + x07) | 0;
    out[oi++] = (y08 + x08) | 0;
    out[oi++] = (y09 + x09) | 0;
    out[oi++] = (y10 + x10) | 0;
    out[oi++] = (y11 + x11) | 0;
    out[oi++] = (y12 + x12) | 0;
    out[oi++] = (y13 + x13) | 0;
    out[oi++] = (y14 + x14) | 0;
    out[oi++] = (y15 + x15) | 0;
}
function BlockMix(input, ii, out, oi, r) {
    // The block B is r 128-byte chunks (which is equivalent of 2r 64-byte chunks)
    let head = oi + 0;
    let tail = oi + 16 * r;
    for (let i = 0; i < 16; i++)
        out[tail + i] = input[ii + (2 * r - 1) * 16 + i]; // X ← B[2r−1]
    for (let i = 0; i < r; i++, head += 16, ii += 16) {
        // We write odd & even Yi at same time. Even: 0bXXXXX0 Odd:  0bXXXXX1
        XorAndSalsa(out, tail, input, ii, out, head); // head[i] = Salsa(blockIn[2*i] ^ tail[i-1])
        if (i > 0)
            tail += 16; // First iteration overwrites tmp value in tail
        XorAndSalsa(out, head, input, (ii += 16), out, tail); // tail[i] = Salsa(blockIn[2*i+1] ^ head[i])
    }
}
// Common prologue and epilogue for sync/async functions
function scryptInit(password, salt, _opts) {
    // Maxmem - 1GB+1KB by default
    const opts = checkOpts({
        dkLen: 32,
        asyncTick: 10,
        maxmem: 1024 ** 3 + 1024,
    }, _opts);
    const { N, r, p, dkLen, asyncTick, maxmem, onProgress } = opts;
    assertNumber(N);
    assertNumber(r);
    assertNumber(p);
    assertNumber(dkLen);
    assertNumber(asyncTick);
    assertNumber(maxmem);
    if (onProgress !== undefined && typeof onProgress !== 'function')
        throw new Error('progressCb should be function');
    const blockSize = 128 * r;
    const blockSize32 = blockSize / 4;
    if (N <= 1 || (N & (N - 1)) !== 0 || N >= 2 ** (blockSize / 8) || N > 2 ** 32) {
        // NOTE: we limit N to be less than 2**32 because of 32 bit variant of Integrify function
        // There is no JS engines that allows alocate more than 4GB per single Uint8Array for now, but can change in future.
        throw new Error('Scrypt: N must be larger than 1, a power of 2, less than 2^(128 * r / 8) and less than 2^32');
    }
    if (p < 0 || p > ((2 ** 32 - 1) * 32) / blockSize) {
        throw new Error('Scrypt: p must be a positive integer less than or equal to ((2^32 - 1) * 32) / (128 * r)');
    }
    if (dkLen < 0 || dkLen > (2 ** 32 - 1) * 32) {
        throw new Error('Scrypt: dkLen should be positive integer less than or equal to (2^32 - 1) * 32');
    }
    const memUsed = blockSize * (N + p);
    if (memUsed > maxmem) {
        throw new Error(`Scrypt: parameters too large, ${memUsed} (128 * r * (N + p)) > ${maxmem} (maxmem)`);
    }
    // [B0...Bp−1] ← PBKDF2HMAC-SHA256(Passphrase, Salt, 1, blockSize*ParallelizationFactor)
    // Since it has only one iteration there is no reason to use async variant
    const B = pbkdf2(sha256, password, salt, { c: 1, dkLen: blockSize * p });
    const B32 = u32(B);
    // Re-used between parallel iterations. Array(iterations) of B
    const V = u32(new Uint8Array(blockSize * N));
    const tmp = u32(new Uint8Array(blockSize));
    let blockMixCb = () => { };
    if (onProgress) {
        const totalBlockMix = 2 * N * p;
        // Invoke callback if progress changes from 10.01 to 10.02
        // Allows to draw smooth progress bar on up to 8K screen
        const callbackPer = Math.max(Math.floor(totalBlockMix / 10000), 1);
        let blockMixCnt = 0;
        blockMixCb = () => {
            blockMixCnt++;
            if (onProgress && (!(blockMixCnt % callbackPer) || blockMixCnt === totalBlockMix))
                onProgress(blockMixCnt / totalBlockMix);
        };
    }
    return { N, r, p, dkLen, blockSize32, V, B32, B, tmp, blockMixCb, asyncTick };
}
function scryptOutput(password, dkLen, B, V, tmp) {
    const res = pbkdf2(sha256, password, B, { c: 1, dkLen });
    B.fill(0);
    V.fill(0);
    tmp.fill(0);
    return res;
}
function scrypt(password, salt, _opts) {
    const { N, r, p, dkLen, blockSize32, V, B32, B, tmp, blockMixCb } = scryptInit(password, salt, _opts);
    for (let pi = 0; pi < p; pi++) {
        const Pi = blockSize32 * pi;
        for (let i = 0; i < blockSize32; i++)
            V[i] = B32[Pi + i]; // V[0] = B[i]
        for (let i = 0, pos = 0; i < N - 1; i++) {
            BlockMix(V, pos, V, (pos += blockSize32), r); // V[i] = BlockMix(V[i-1]);
            blockMixCb();
        }
        BlockMix(V, (N - 1) * blockSize32, B32, Pi, r); // Process last element
        blockMixCb();
        for (let i = 0; i < N; i++) {
            // First u32 of the last 64-byte block (u32 is LE)
            const j = B32[Pi + blockSize32 - 16] % N; // j = Integrify(X) % iterations
            for (let k = 0; k < blockSize32; k++)
                tmp[k] = B32[Pi + k] ^ V[j * blockSize32 + k]; // tmp = B ^ V[j]
            BlockMix(tmp, 0, B32, Pi, r); // B = BlockMix(B ^ V[j])
            blockMixCb();
        }
    }
    return scryptOutput(password, dkLen, B, V, tmp);
}

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
class Prng {
    /* eslint-disable-next-line class-methods-use-this */
    random(numBytes) {
        return Array.from(crypto.getRandomValues(new Uint8Array(numBytes)));
    }
}
class Hash {
    constructor(name) {
        this.name = name;
        switch (name) {
            case Hash.ID.SHA1:
                this.Nh = 20;
                break;
            case Hash.ID.SHA256:
                this.Nh = 32;
                break;
            case Hash.ID.SHA384:
                this.Nh = 48;
                break;
            case Hash.ID.SHA512:
                this.Nh = 64;
                break;
            default:
                throw new Error(`invalid hash name: ${name}`);
        }
    }
    async sum(msg) {
        return new Uint8Array(await crypto.subtle.digest(this.name, msg));
    }
}
/* eslint-disable-next-line @typescript-eslint/no-namespace */
(function (Hash) {
    Hash.ID = {
        SHA1: 'SHA-1',
        SHA256: 'SHA-256',
        SHA384: 'SHA-384',
        SHA512: 'SHA-512'
    };
})(Hash || (Hash = {}));
class Hmac {
    constructor(hash) {
        this.hash = hash;
        this.Nm = new Hash(hash).Nh;
    }
    async with_key(key) {
        return new Hmac.Macops(await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: this.hash }, false, [
            'sign'
        ]));
    }
}
Hmac.Macops = class {
    constructor(crypto_key) {
        this.crypto_key = crypto_key;
    }
    async sign(msg) {
        return new Uint8Array(await crypto.subtle.sign(this.crypto_key.algorithm.name, this.crypto_key, msg));
    }
    async verify(msg, output) {
        return ctEqual(output, await this.sign(msg));
    }
};
class Hkdf {
    constructor(hash) {
        this.hash = hash;
        this.Nx = new Hmac(hash).Nm;
    }
    async extract(salt, ikm) {
        return (await new Hmac(this.hash).with_key(salt)).sign(ikm);
    }
    async expand(prk, info, lenBytes) {
        const hashLen = new Hash(this.hash).Nh;
        const N = Math.ceil(lenBytes / hashLen);
        const T = new Uint8Array(N * hashLen);
        const hm = await new Hmac(this.hash).with_key(prk);
        let Ti = new Uint8Array();
        let offset = 0;
        for (let i = 0; i < N; i++) {
            Ti = await hm.sign(joinAll([Ti, info, Uint8Array.of(i + 1)])); // eslint-disable-line no-await-in-loop
            T.set(Ti, offset);
            offset += hashLen;
        }
        return T.slice(0, lenBytes);
    }
}
const IdentityMemHardFn = { name: 'Identity', harden: (x) => x };
const ScryptMemHardFn = {
    name: 'scrypt',
    harden: (msg) => scrypt(msg, new Uint8Array(), { N: 32768, r: 8, p: 1 })
};

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
var OpaqueID;
(function (OpaqueID) {
    OpaqueID[OpaqueID["OPAQUE_P256"] = 3] = "OPAQUE_P256";
    OpaqueID[OpaqueID["OPAQUE_P384"] = 4] = "OPAQUE_P384";
    OpaqueID[OpaqueID["OPAQUE_P521"] = 5] = "OPAQUE_P521";
})(OpaqueID || (OpaqueID = {}));
class OpaqueConfig {
    constructor(opaqueID) {
        this.opaqueID = opaqueID;
        let oprfID = 0;
        switch (opaqueID) {
            case OpaqueID.OPAQUE_P256:
                oprfID = OprfID.OPRF_P256_SHA256;
                break;
            case OpaqueID.OPAQUE_P384:
                oprfID = OprfID.OPRF_P384_SHA384;
                break;
            case OpaqueID.OPAQUE_P521:
                oprfID = OprfID.OPRF_P521_SHA512;
                break;
            default:
                throw new Error('invalid opaque id');
        }
        this.constants = { Nn: 32, Nseed: 32 };
        this.prng = new Prng();
        this.oprf = new OPRFBaseMode(oprfID);
        this.hash = new Hash(this.oprf.hash);
        this.mac = new Hmac(this.hash.name);
        this.kdf = new Hkdf(this.hash.name);
        this.ake = new AKE3DH(this.oprf.id);
    }
    toString() {
        return (`${OpaqueID[this.opaqueID]} = {` +
            `OPRF: ${this.oprf.name}, ` +
            `Hash: ${this.hash.name}}`);
    }
}
function getOpaqueConfig(opaqueID) {
    return new OpaqueConfig(opaqueID);
}

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
class Serializable {
    static check_string(a) {
        if (typeof a === 'string') {
            return true;
        }
        throw new Error('string expected');
    }
    static check_uint8array(a) {
        if (a instanceof Uint8Array) {
            return true;
        }
        throw new Error('Uint8Array expected');
    }
    static check_uint8arrays(as) {
        return as.every(this.check_uint8array);
    }
    static check_bytes_array(a) {
        if (!Array.isArray(a) ||
            !a.every((element) => Number.isInteger(element) && element >= 0 && element <= 255)) {
            throw new Error('Array of byte-sized integers expected');
        }
        return true;
    }
    static check_bytes_arrays(as) {
        return as.every(this.check_bytes_array);
    }
    static sizeSerialized(_) {
        throw new Error('child class must implement');
    }
    static checked_bytes_to_uint8array(cfg, bytes) {
        this.check_bytes_array(bytes);
        const u8array = Uint8Array.from(bytes);
        this.checked_object(cfg, u8array);
        return u8array;
    }
    static checked_object(cfg, u8array) {
        checked_vector(u8array, this.sizeSerialized(cfg), this.name);
    }
}
class Envelope extends Serializable {
    constructor(cfg, nonce, auth_tag) {
        super();
        this.nonce = checked_vector(nonce, cfg.constants.Nn);
        this.auth_tag = checked_vector(auth_tag, cfg.mac.Nm);
    }
    serialize() {
        return Array.from(joinAll([this.nonce, this.auth_tag]));
    }
    static sizeSerialized(cfg) {
        return cfg.constants.Nn + cfg.mac.Nm;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.constants.Nn;
        const nonce = u8array.slice(start, end);
        start = end;
        end += cfg.mac.Nm;
        const auth_tag = u8array.slice(start, end);
        return new Envelope(cfg, nonce, auth_tag);
    }
}
class RegistrationRequest extends Serializable {
    constructor(cfg, data) {
        Serializable.check_uint8array(data);
        super();
        this.data = checked_vector(data, cfg.oprf.Noe);
    }
    serialize() {
        return Array.from(this.data);
    }
    static sizeSerialized(cfg) {
        return cfg.oprf.Noe;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        const start = 0;
        const end = cfg.oprf.Noe;
        const data = u8array.slice(start, end);
        return new RegistrationRequest(cfg, data);
    }
}
class RegistrationResponse extends Serializable {
    constructor(cfg, data, server_public_key) {
        Serializable.check_uint8arrays([data, server_public_key]);
        super();
        this.evaluation = checked_vector(data, cfg.oprf.Noe);
        this.server_public_key = checked_vector(server_public_key, cfg.ake.Npk);
    }
    serialize() {
        return Array.from(joinAll([this.evaluation, this.server_public_key]));
    }
    static sizeSerialized(cfg) {
        return cfg.oprf.Noe + cfg.ake.Npk;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.oprf.Noe;
        const evaluation = u8array.slice(start, end);
        start = end;
        end += cfg.ake.Npk;
        const server_public_key = u8array.slice(start, end);
        return new RegistrationResponse(cfg, evaluation, server_public_key);
    }
}
class RegistrationRecord extends Serializable {
    constructor(cfg, client_public_key, masking_key, envelope) {
        Serializable.check_uint8arrays([client_public_key, masking_key]);
        super();
        this.client_public_key = checked_vector(client_public_key, cfg.ake.Npk);
        this.masking_key = checked_vector(masking_key, cfg.hash.Nh);
        this.envelope = envelope;
    }
    serialize() {
        return Array.from(joinAll([
            this.client_public_key,
            this.masking_key,
            Uint8Array.from(this.envelope.serialize())
        ]));
    }
    static sizeSerialized(cfg) {
        return cfg.ake.Npk + cfg.hash.Nh + Envelope.sizeSerialized(cfg);
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.ake.Npk;
        const client_public_key = u8array.slice(start, end);
        start = end;
        end += cfg.hash.Nh;
        const masking_key = u8array.slice(start, end);
        start = end;
        end += Envelope.sizeSerialized(cfg);
        const envelope_bytes = u8array.slice(start, end);
        const envelope = Envelope.deserialize(cfg, Array.from(envelope_bytes));
        return new RegistrationRecord(cfg, client_public_key, masking_key, envelope);
    }
    static async createFake(cfg) {
        const seed = cfg.prng.random(cfg.constants.Nseed);
        const { public_key: client_public_key } = await cfg.ake.deriveAuthKeyPair(new Uint8Array(seed));
        const masking_key = new Uint8Array(cfg.prng.random(cfg.hash.Nh));
        const envelope = Envelope.deserialize(cfg, new Array(Envelope.sizeSerialized(cfg)).fill(0));
        return new RegistrationRecord(cfg, client_public_key, masking_key, envelope);
    }
}
class CredentialRequest extends Serializable {
    constructor(cfg, data) {
        Serializable.check_uint8array(data);
        super();
        this.data = checked_vector(data, cfg.oprf.Noe);
    }
    serialize() {
        return Array.from(this.data);
    }
    static sizeSerialized(cfg) {
        return cfg.oprf.Noe;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        const start = 0;
        const end = cfg.oprf.Noe;
        const data = u8array.slice(start, end);
        return new CredentialRequest(cfg, data);
    }
}
class CredentialResponse extends Serializable {
    constructor(cfg, evaluation, masking_nonce, masked_response) {
        Serializable.check_uint8arrays([masking_nonce, masked_response]);
        super();
        this.evaluation = evaluation;
        this.masking_nonce = checked_vector(masking_nonce, cfg.constants.Nn);
        this.masked_response = checked_vector(masked_response, cfg.ake.Npk + Envelope.sizeSerialized(cfg));
    }
    serialize() {
        return Array.from(joinAll([this.evaluation, this.masking_nonce, this.masked_response]));
    }
    static sizeSerialized(cfg) {
        return cfg.oprf.Noe + cfg.constants.Nn + cfg.ake.Npk + Envelope.sizeSerialized(cfg);
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.oprf.Noe;
        const evaluation_bytes = u8array.slice(start, end);
        const evaluation = checked_vector(evaluation_bytes, cfg.oprf.Noe);
        start = end;
        end += cfg.constants.Nn;
        const masking_nonce = u8array.slice(start, end);
        start = end;
        end += cfg.ake.Npk + Envelope.sizeSerialized(cfg);
        const masked_response = u8array.slice(start, end);
        return new CredentialResponse(cfg, evaluation, masking_nonce, masked_response);
    }
}
class CredentialFile extends Serializable {
    constructor(credential_identifier, record, client_identity) {
        if (!(Serializable.check_string(credential_identifier) &&
            (client_identity ? Serializable.check_string(client_identity) : true))) {
            throw new Error('expected string inputs');
        }
        super();
        this.credential_identifier = credential_identifier;
        this.record = record;
        this.client_identity = client_identity;
    }
    serialize() {
        const te = new TextEncoder();
        return Array.from(joinAll([
            encode_vector_16(te.encode(this.credential_identifier)),
            Uint8Array.from(this.record.serialize()),
            encode_vector_16(te.encode(this.client_identity))
        ]));
    }
    static sizeSerialized(cfg) {
        // This is the minimum size of a valid CredentialFile.
        return (2 + // Size of header for credential_identifier.
            RegistrationRecord.sizeSerialized(cfg) +
            2 // Size of header for client_identity.
        );
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        const td = new TextDecoder();
        const res = decode_vector_16(u8array);
        const credential_identifier = td.decode(res.payload);
        let start = 0;
        let end = res.consumed;
        start = end;
        end += RegistrationRecord.sizeSerialized(cfg);
        const record = RegistrationRecord.deserialize(cfg, Array.from(u8array.slice(start, end)));
        start = end;
        const { payload } = decode_vector_16(u8array.slice(start));
        const client_identity = payload.length === 0 ? undefined : td.decode(payload); // eslint-disable-line no-undefined
        return new CredentialFile(credential_identifier, record, client_identity);
    }
}
class AuthInit extends Serializable {
    constructor(cfg, client_nonce, client_keyshare) {
        Serializable.check_uint8arrays([client_nonce, client_keyshare]);
        super();
        this.client_nonce = checked_vector(client_nonce, cfg.constants.Nn);
        this.client_keyshare = checked_vector(client_keyshare, cfg.ake.Npk);
    }
    serialize() {
        return Array.from(joinAll([this.client_nonce, this.client_keyshare]));
    }
    static sizeSerialized(cfg) {
        return cfg.constants.Nn + cfg.ake.Npk;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.constants.Nn;
        const client_nonce = u8array.slice(start, end);
        start = end;
        end += cfg.ake.Npk;
        const client_keyshare = u8array.slice(start, end);
        return new AuthInit(cfg, client_nonce, client_keyshare);
    }
}
class AuthResponse extends Serializable {
    constructor(cfg, server_nonce, server_keyshare, server_mac) {
        Serializable.check_uint8arrays([server_nonce, server_keyshare, server_mac]);
        super();
        this.server_nonce = checked_vector(server_nonce, cfg.constants.Nn);
        this.server_keyshare = checked_vector(server_keyshare, cfg.ake.Npk);
        this.server_mac = checked_vector(server_mac, cfg.mac.Nm);
    }
    serialize() {
        return Array.from(joinAll([this.server_nonce, this.server_keyshare, this.server_mac]));
    }
    static sizeSerialized(cfg) {
        return cfg.constants.Nn + cfg.ake.Npk + cfg.mac.Nm;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.constants.Nn;
        const server_nonce = u8array.slice(start, end);
        start = end;
        end += cfg.ake.Npk;
        const server_keyshare = u8array.slice(start, end);
        start = end;
        end += cfg.mac.Nm;
        const server_mac = u8array.slice(start, end);
        return new AuthResponse(cfg, server_nonce, server_keyshare, server_mac);
    }
}
class AuthFinish extends Serializable {
    constructor(cfg, client_mac) {
        Serializable.check_uint8array(client_mac);
        super();
        this.client_mac = checked_vector(client_mac, cfg.mac.Nm);
    }
    serialize() {
        return Array.from(this.client_mac.slice());
    }
    static sizeSerialized(cfg) {
        return cfg.mac.Nm;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        const start = 0;
        const end = cfg.mac.Nm;
        const client_mac = u8array.slice(start, end);
        return new AuthFinish(cfg, client_mac);
    }
}
class ExpectedAuthResult extends Serializable {
    constructor(cfg, expected_client_mac, session_key) {
        Serializable.check_uint8arrays([expected_client_mac, session_key]);
        super();
        this.expected_client_mac = checked_vector(expected_client_mac, cfg.mac.Nm);
        this.session_key = checked_vector(session_key, cfg.kdf.Nx);
    }
    serialize() {
        return Array.from(joinAll([this.expected_client_mac, this.session_key]));
    }
    static sizeSerialized(cfg) {
        return cfg.mac.Nm + cfg.kdf.Nx;
    }
    static deserialize(cfg, bytes) {
        const u8array = this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = cfg.mac.Nm;
        const expected_client_mac = u8array.slice(start, end);
        start = end;
        end += cfg.kdf.Nx;
        const session_key = u8array.slice(start, end);
        return new ExpectedAuthResult(cfg, expected_client_mac, session_key);
    }
}
class KE1 extends Serializable {
    constructor(request, auth_init) {
        super();
        this.request = request;
        this.auth_init = auth_init;
    }
    serialize() {
        return [...this.request.serialize(), ...this.auth_init.serialize()];
    }
    static sizeSerialized(cfg) {
        return CredentialRequest.sizeSerialized(cfg) + AuthInit.sizeSerialized(cfg);
    }
    static deserialize(cfg, bytes) {
        this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = CredentialRequest.sizeSerialized(cfg);
        const request = CredentialRequest.deserialize(cfg, bytes.slice(start, end));
        start = end;
        end += AuthInit.sizeSerialized(cfg);
        const auth_init = AuthInit.deserialize(cfg, bytes.slice(start, end));
        return new KE1(request, auth_init);
    }
}
class KE2 extends Serializable {
    constructor(response, auth_response) {
        super();
        this.response = response;
        this.auth_response = auth_response;
    }
    serialize() {
        return [...this.response.serialize(), ...this.auth_response.serialize()];
    }
    static sizeSerialized(cfg) {
        return CredentialResponse.sizeSerialized(cfg) + AuthResponse.sizeSerialized(cfg);
    }
    static deserialize(cfg, bytes) {
        this.checked_bytes_to_uint8array(cfg, bytes);
        let start = 0;
        let end = CredentialResponse.sizeSerialized(cfg);
        const response = CredentialResponse.deserialize(cfg, bytes.slice(start, end));
        start = end;
        end += AuthResponse.sizeSerialized(cfg);
        const auth_response = AuthResponse.deserialize(cfg, bytes.slice(start, end));
        return new KE2(response, auth_response);
    }
}
class KE3 extends Serializable {
    constructor(auth_finish) {
        super();
        this.auth_finish = auth_finish;
    }
    serialize() {
        return this.auth_finish.serialize();
    }
    static sizeSerialized(cfg) {
        return AuthFinish.sizeSerialized(cfg);
    }
    static deserialize(cfg, bytes) {
        this.checked_bytes_to_uint8array(cfg, bytes);
        const start = 0;
        const end = Number(AuthFinish.sizeSerialized(cfg));
        const auth_finish = AuthFinish.deserialize(cfg, bytes.slice(start, end));
        return new KE3(auth_finish);
    }
}

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
class AKE3DHClient {
    constructor(config) {
        this.config = config;
    }
    async start() {
        const client_nonce = this.config.prng.random(this.config.constants.Nn);
        const { private_key: client_secret, public_key: client_keyshare } = await this.config.ake.generateAuthKeyPair();
        this.client_secret = new Uint8Array(client_secret);
        return new AuthInit(this.config, new Uint8Array(client_nonce), new Uint8Array(client_keyshare));
    }
    async finalize(client_identity, client_private_key, server_identity, server_public_key, ke1, ke2, context) {
        if (typeof this.client_secret === 'undefined') {
            return new Error('ake3dhclient has not started yet');
        }
        const ikm = tripleDH_IKM(this.config, [
            { sk: this.client_secret, pk: ke2.auth_response.server_keyshare },
            { sk: this.client_secret, pk: server_public_key },
            { sk: client_private_key, pk: ke2.auth_response.server_keyshare }
        ]);
        const preamble = preambleBuild(ke1, ke2, server_identity, client_identity, context);
        const { Km2, Km3, session_key } = await deriveKeys(this.config, ikm, preamble);
        const h_preamble = await this.config.hash.sum(preamble);
        if (!(await (await this.config.mac.with_key(Km2)).verify(h_preamble, ke2.auth_response.server_mac))) {
            return new Error('handshake error');
        }
        const hmacData = await this.config.hash.sum(joinAll([preamble, ke2.auth_response.server_mac]));
        const client_mac = await (await this.config.mac.with_key(Km3)).sign(hmacData);
        const auth_finish = new AuthFinish(this.config, client_mac);
        return { auth_finish, session_key };
    }
}

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
class CleartextCredentials {
    constructor(cfg, server_public_key, client_public_key, server_identity, client_identity) {
        this.server_public_key = checked_vector(server_public_key, cfg.ake.Npk);
        this.server_identity = server_identity ? server_identity : server_public_key;
        this.client_identity = client_identity ? client_identity : client_public_key;
    }
    serialize() {
        return Array.from(joinAll([
            this.server_public_key,
            encode_vector_16(this.server_identity),
            encode_vector_16(this.client_identity)
        ]));
    }
}
async function expand_keys(cfg, randomized_pwd, envelope_nonce) {
    const auth_key = await cfg.kdf.expand(randomized_pwd, joinAll([envelope_nonce, Uint8Array.from(LABELS.AuthKey)]), cfg.hash.Nh);
    const export_key = await cfg.kdf.expand(randomized_pwd, joinAll([envelope_nonce, Uint8Array.from(LABELS.ExportKey)]), cfg.hash.Nh);
    const seed = await cfg.kdf.expand(randomized_pwd, joinAll([envelope_nonce, Uint8Array.from(LABELS.PrivateKey)]), cfg.constants.Nseed);
    const client_ake_keypair = await cfg.ake.deriveAuthKeyPair(seed);
    return { auth_key, export_key, client_ake_keypair };
}
async function store(cfg, randomized_pwd, server_public_key, server_identity, client_identity) {
    const envelope_nonce = new Uint8Array(cfg.prng.random(cfg.constants.Nn));
    const { auth_key, export_key, client_ake_keypair } = await expand_keys(cfg, randomized_pwd, envelope_nonce);
    const { public_key: client_public_key } = client_ake_keypair;
    const cleartext_creds = new CleartextCredentials(cfg, server_public_key, client_public_key, server_identity, client_identity);
    const auth_msg = joinAll([envelope_nonce, Uint8Array.from(cleartext_creds.serialize())]);
    const auth_tag = await (await cfg.mac.with_key(auth_key)).sign(auth_msg);
    const envelope = new Envelope(cfg, envelope_nonce, auth_tag);
    const masking_key = await cfg.kdf.expand(randomized_pwd, Uint8Array.from(LABELS.MaskingKey), cfg.hash.Nh);
    return { envelope, client_public_key, masking_key, export_key };
}
async function recover(cfg, envelope, randomized_pwd, server_public_key, server_identity, client_identity) {
    const { auth_key, export_key, client_ake_keypair } = await expand_keys(cfg, randomized_pwd, envelope.nonce);
    const { public_key: client_public_key } = client_ake_keypair;
    const cleartext_creds = new CleartextCredentials(cfg, server_public_key, client_public_key, server_identity, client_identity);
    const auth_msg = joinAll([envelope.nonce, Uint8Array.from(cleartext_creds.serialize())]);
    const mac = await cfg.mac.with_key(auth_key);
    if (!(await mac.verify(auth_msg, envelope.auth_tag))) {
        return new Error('EnvelopeRecoveryError');
    }
    return { client_ake_keypair, export_key };
}
class OpaqueCoreClient {
    constructor(config, memHard = ScryptMemHardFn) {
        this.config = config;
        this.memHard = memHard;
    }
    async createRegistrationRequest(password) {
        const { blindedElement: M, blind } = await this.config.oprf.blind(password);
        const request = new RegistrationRequest(this.config, M);
        return { request, blind };
    }
    async finalizeRequest(password, blind, response, server_identity, client_identity) {
        const y = await this.config.oprf.finalize(password, blind, response.evaluation);
        const nosalt = new Uint8Array(this.config.hash.Nh);
        const randomized_pwd = await this.config.kdf.extract(nosalt, joinAll([y, this.memHard.harden(y)]));
        const { envelope, client_public_key, masking_key, export_key } = await store(this.config, randomized_pwd, response.server_public_key, server_identity, client_identity);
        const record = new RegistrationRecord(this.config, client_public_key, masking_key, envelope);
        return { record, export_key: Array.from(export_key) };
    }
    async createCredentialRequest(password) {
        const { blindedElement: M, blind } = await this.config.oprf.blind(password);
        const request = new CredentialRequest(this.config, M);
        return { request, blind };
    }
    async recoverCredentials(password, blind, response, server_identity, client_identity) {
        const y = await this.config.oprf.finalize(password, blind, response.evaluation);
        const nosalt = new Uint8Array(this.config.hash.Nh);
        const randomized_pwd = await this.config.kdf.extract(nosalt, joinAll([y, this.memHard.harden(y)]));
        const masking_key = await this.config.kdf.expand(randomized_pwd, Uint8Array.from(LABELS.MaskingKey), this.config.hash.Nh);
        const Ne = Envelope.sizeSerialized(this.config);
        const credential_response_pad = await this.config.kdf.expand(masking_key, joinAll([response.masking_nonce, Uint8Array.from(LABELS.CredentialResponsePad)]), this.config.ake.Npk + Ne);
        const server_pub_key_enve = xor(credential_response_pad, response.masked_response);
        const server_public_key = server_pub_key_enve.slice(0, this.config.ake.Npk);
        const { Npk } = this.config.ake;
        const envelope_bytes = server_pub_key_enve.slice(Npk, Npk + Ne);
        const envelope = Envelope.deserialize(this.config, Array.from(envelope_bytes));
        const rec = await recover(this.config, envelope, randomized_pwd, server_public_key, server_identity, client_identity);
        if (rec instanceof Error) {
            return rec;
        }
        return { server_public_key, ...rec };
    }
}

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
class OpaqueClient {
    constructor(config, memHard = ScryptMemHardFn) {
        this.config = config;
        this.status = OpaqueClient.States.NEW;
        this.opaque_core = new OpaqueCoreClient(config, memHard);
        this.ake = new AKE3DHClient(this.config);
    }
    async registerInit(password) {
        if (this.status !== OpaqueClient.States.NEW) {
            return new Error('client not ready');
        }
        const password_uint8array = new TextEncoder().encode(password);
        const { request, blind } = await this.opaque_core.createRegistrationRequest(password_uint8array);
        this.blind = blind;
        this.password = password_uint8array;
        this.status = OpaqueClient.States.REG_STARTED;
        return request;
    }
    async registerFinish(response, server_identity, client_identity) {
        if (this.status !== OpaqueClient.States.REG_STARTED ||
            typeof this.password === 'undefined' ||
            typeof this.blind === 'undefined') {
            return new Error('client not ready');
        }
        const te = new TextEncoder();
        // eslint-disable-next-line no-undefined
        const server_identity_u8array = server_identity ? te.encode(server_identity) : undefined;
        // eslint-disable-next-line no-undefined
        const client_identity_u8array = client_identity ? te.encode(client_identity) : undefined;
        const out = await this.opaque_core.finalizeRequest(this.password, this.blind, response, server_identity_u8array, client_identity_u8array);
        this.clean();
        return out;
    }
    async authInit(password) {
        if (this.status !== OpaqueClient.States.NEW) {
            return new Error('client not ready');
        }
        const password_u8array = new TextEncoder().encode(password);
        const { request, blind } = await this.opaque_core.createCredentialRequest(password_u8array);
        const auth_init = await this.ake.start();
        const ke1 = new KE1(request, auth_init);
        this.blind = blind;
        this.password = password_u8array;
        this.ke1 = ke1;
        this.status = OpaqueClient.States.LOG_STARTED;
        return ke1;
    }
    async authFinish(ke2, server_identity, client_identity, context) {
        if (this.status !== OpaqueClient.States.LOG_STARTED ||
            typeof this.password === 'undefined' ||
            typeof this.blind === 'undefined' ||
            typeof this.ke1 === 'undefined') {
            return new Error('client not ready');
        }
        const te = new TextEncoder();
        // eslint-disable-next-line no-undefined
        const server_identity_u8array = server_identity ? te.encode(server_identity) : undefined;
        // eslint-disable-next-line no-undefined
        const client_identity_u8array = client_identity ? te.encode(client_identity) : undefined;
        const context_u8array = context ? te.encode(context) : new Uint8Array(0);
        const rec = await this.opaque_core.recoverCredentials(this.password, this.blind, ke2.response, server_identity_u8array, client_identity_u8array);
        if (rec instanceof Error) {
            return rec;
        }
        const { client_ake_keypair, server_public_key, export_key } = rec;
        const fin = await this.ake.finalize(client_identity_u8array ? client_identity_u8array : client_ake_keypair.public_key, client_ake_keypair.private_key, server_identity_u8array ? server_identity_u8array : server_public_key, server_public_key, this.ke1, ke2, context_u8array);
        if (fin instanceof Error) {
            return fin;
        }
        const { auth_finish, session_key } = fin;
        const ke3 = new KE3(auth_finish);
        this.clean();
        return { ke3, session_key: Array.from(session_key), export_key: Array.from(export_key) };
    }
    clean() {
        this.status = OpaqueClient.States.NEW;
        this.password = undefined; // eslint-disable-line no-undefined
        this.blind = undefined; // eslint-disable-line no-undefined
        this.ke1 = undefined; // eslint-disable-line no-undefined
    }
}
OpaqueClient.States = {
    NEW: 0,
    REG_STARTED: 1,
    LOG_STARTED: 2
};

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
class AKE3DHServer {
    constructor(config) {
        this.config = config;
    }
    async response(server_private_key, server_identity, ke1, credential_response, context, client_public_key, client_identity) {
        const server_nonce = this.config.prng.random(this.config.constants.Nn);
        const { private_key: server_secret, public_key: server_keyshare } = await this.config.ake.generateAuthKeyPair();
        const tmp_server_mac = new Uint8Array(this.config.mac.Nm);
        const auth_response = new AuthResponse(this.config, new Uint8Array(server_nonce), new Uint8Array(server_keyshare), tmp_server_mac);
        const ke2 = new KE2(credential_response, auth_response);
        const preamble = preambleBuild(ke1, ke2, server_identity, client_identity ? client_identity : client_public_key, context);
        const ikm = tripleDH_IKM(this.config, [
            { sk: new Uint8Array(server_secret), pk: ke1.auth_init.client_keyshare },
            { sk: server_private_key, pk: ke1.auth_init.client_keyshare },
            { sk: new Uint8Array(server_secret), pk: client_public_key }
        ]);
        const { Km2, Km3, session_key } = await deriveKeys(this.config, ikm, preamble);
        const h_preamble = await this.config.hash.sum(preamble);
        const server_mac = await (await this.config.mac.with_key(Km2)).sign(h_preamble);
        const h_preamble_mac = await this.config.hash.sum(joinAll([preamble, server_mac]));
        const expected_client_mac = await (await this.config.mac.with_key(Km3)).sign(h_preamble_mac);
        const expected = new ExpectedAuthResult(this.config, expected_client_mac, session_key);
        ke2.auth_response.server_mac = checked_vector(server_mac, this.config.mac.Nm);
        return { ke2, expected };
    }
    // eslint-disable-next-line class-methods-use-this
    finish(auth_finish, expected) {
        if (!ctEqual(auth_finish.client_mac, expected.expected_client_mac)) {
            return new Error('handshake error');
        }
        return { session_key: Array.from(expected.session_key) };
    }
}

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
class OpaqueCoreServer {
    constructor(config, oprf_seed) {
        this.config = config;
        this.oprf_seed = checked_vector(oprf_seed, config.hash.Nh);
    }
    async doOPRFEvaluation(blinded, credential_identifier) {
        const oprf_key_seed = await this.config.kdf.expand(this.oprf_seed, joinAll([credential_identifier, Uint8Array.from(LABELS.OprfKey)]), this.config.constants.Nseed);
        const oprf_key = await this.config.oprf.deriveOPRFKey(oprf_key_seed);
        return this.config.oprf.evaluate(oprf_key, blinded);
    }
    async createRegistrationResponse(request, server_public_key, credential_identifier) {
        const evaluation = await this.doOPRFEvaluation(request.data, credential_identifier);
        return new RegistrationResponse(this.config, evaluation, server_public_key);
    }
    async createCredentialResponse(request, record, server_public_key, credential_identifier) {
        const evaluation = await this.doOPRFEvaluation(request.data, credential_identifier);
        const masking_nonce = new Uint8Array(this.config.prng.random(this.config.constants.Nn));
        const Ne = Envelope.sizeSerialized(this.config);
        const credential_response_pad = await this.config.kdf.expand(record.masking_key, joinAll([masking_nonce, Uint8Array.from(LABELS.CredentialResponsePad)]), this.config.ake.Npk + Ne);
        const plaintext = joinAll([server_public_key, Uint8Array.from(record.envelope.serialize())]);
        const masked_response = xor(credential_response_pad, plaintext);
        return new CredentialResponse(this.config, evaluation, masking_nonce, masked_response);
    }
}

// Copyright (c) 2021 Cloudflare, Inc. and contributors.
class OpaqueServer {
    constructor(config, oprf_seed, ake_keypair_export, server_identity) {
        this.config = config;
        Serializable.check_bytes_arrays([
            ake_keypair_export.public_key,
            ake_keypair_export.private_key
        ]);
        this.ake_keypair = {
            private_key: new Uint8Array(ake_keypair_export.private_key),
            public_key: new Uint8Array(ake_keypair_export.public_key)
        };
        Serializable.check_bytes_array(oprf_seed);
        this.server_identity = server_identity
            ? new TextEncoder().encode(server_identity)
            : this.ake_keypair.public_key;
        this.opaque_core = new OpaqueCoreServer(config, new Uint8Array(oprf_seed));
        this.ake = new AKE3DHServer(this.config);
    }
    registerInit(request, credential_identifier) {
        return this.opaque_core.createRegistrationResponse(request, this.ake_keypair.public_key, new TextEncoder().encode(credential_identifier));
    }
    async authInit(ke1, record, credential_identifier, client_identity, context) {
        const credential_identifier_u8array = new TextEncoder().encode(credential_identifier);
        const response = await this.opaque_core.createCredentialResponse(ke1.request, record, this.ake_keypair.public_key, credential_identifier_u8array);
        const te = new TextEncoder();
        // eslint-disable-next-line no-undefined
        const client_identity_u8array = client_identity ? te.encode(client_identity) : undefined;
        const context_u8array = context ? te.encode(context) : new Uint8Array(0);
        return this.ake.response(this.ake_keypair.private_key, this.server_identity, ke1, response, context_u8array, record.client_public_key, client_identity_u8array);
    }
    authFinish(ke3, expected) {
        return this.ake.finish(ke3.auth_finish, expected);
    }
}

export { CredentialFile, ExpectedAuthResult, IdentityMemHardFn, KE1, KE2, KE3, OpaqueClient, OpaqueID, OpaqueServer, RegistrationRecord, RegistrationRequest, RegistrationResponse, ScryptMemHardFn, getOpaqueConfig };
