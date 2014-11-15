/** 
* @fileOverview crypto implementation, a wrapper to CryptoJS
* @author <a href="jamol@live.com">Fengping Bao</a>
* @version 0.1 
*/
; (function (SrtpJS, CryptoJS, undefined) {
    var exports = SrtpJS,
        crypto = exports.crypto || {}
    ;

    SrtpJS.extend(crypto, {
        AES_BLOCK_SIZE: 16,
        aesCtrEncrypt: function (data, key, iv) {
            if (!CryptoJS) {
                return null;
            }
            var e = CryptoJS.AES.encrypt(CryptoJS.lib.WordArray.create(data), CryptoJS.lib.WordArray.create(key),
                { mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding, iv: CryptoJS.lib.WordArray.create(iv) });
            return wordArrayToUint8Array(e.ciphertext);
        },

        aesCtrDecrypt: function (data, key, iv) {
            if (!CryptoJS) {
                return null;
            }
            var p = { ciphertext: CryptoJS.lib.WordArray.create(data) };
            var words = CryptoJS.AES.decrypt(p, CryptoJS.lib.WordArray.create(key),
                { mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding, iv: CryptoJS.lib.WordArray.create(iv) });
            return wordArrayToUint8Array(words);
        },

        aesEcbEncrypt: function (data, key) {
            if (!CryptoJS) {
                return null;
            }
            var e = CryptoJS.AES.encrypt(CryptoJS.lib.WordArray.create(data), CryptoJS.lib.WordArray.create(key),
		        { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding });
            return wordArrayToUint8Array(e.ciphertext);
        },

        aesEcbDecrypt: function (data, key) {
            if (!CryptoJS) {
                return null;
            }
            var p = { ciphertext: CryptoJS.lib.WordArray.create(data) };
            var words = CryptoJS.AES.decrypt(p, CryptoJS.lib.WordArray.create(key),
		        { mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding });
            return wordArrayToUint8Array(words);
        },

        hmacSha1: function (data, key) {
            if (!CryptoJS) {
                return null;
            }
            var h = CryptoJS.HmacSHA1(CryptoJS.lib.WordArray.create(data), CryptoJS.lib.WordArray.create(key));
            return wordArrayToUint8Array(h);
        },

        hmacSha1List: function (bufList, key) {
            if (!CryptoJS) {
                return null;
            }
            var hmac = CryptoJS.algo.HMAC.create(CryptoJS.algo.SHA1, CryptoJS.lib.WordArray.create(key));
            for (var i = 0; i < bufList.length; ++i) {
                hmac.update(CryptoJS.lib.WordArray.create(bufList[i]));
            }
            var h = hmac.finalize();
            return wordArrayToUint8Array(h);
        },

        /**
         * @description generate random key
         * @function SrtpJS.crypto.generateKey
         * @param {Integer} keyLength the length of key
         * @returns {Uint8Array} return the key
         */
        generateKey: function (keyLength) {
            var r1, r2, kek, iv, key;
            r1 = Math.ceil(Math.random() * 0xFFFFFFFF);
            r2 = Math.ceil(Math.random() * 0xFFFFFFFF);
            kek = new Uint8Array(crypto.AES_BLOCK_SIZE);
            kek[0] = (r1 >>> 24) & 0xFF;
            kek[1] = (r1 >>> 16) & 0xFF;
            kek[2] = (r1 >>> 8) & 0xFF;
            kek[3] = r1 & 0xFF;
            iv = new Uint8Array(crypto.AES_BLOCK_SIZE);
            iv[0] = (r2 >>> 24) & 0xFF;
            iv[1] = (r2 >>> 16) & 0xFF;
            iv[2] = (r2 >>> 8) & 0xFF;
            iv[3] = r2 & 0xFF;
            key = new Uint8Array(keyLength);
            key = crypto.aesCtrEncrypt(key, kek, iv);
            return key;
        },

        /**
         * @description generate random key
         * @function SrtpJS.crypto.generateKeyBase64
         * @param {Integer} keyLength the length of key
         * @returns {String} return the key that is base64-ed
         */
        generateKeyBase64: function (keyLength) {
            var r1, r2, kek, iv, key;
            r1 = Math.ceil(Math.random() * 0xFFFFFFFF);
            r2 = Math.ceil(Math.random() * 0xFFFFFFFF);
            kek = new Uint8Array(crypto.AES_BLOCK_SIZE);
            kek[0] = (r1 >>> 24) & 0xFF;
            kek[1] = (r1 >>> 16) & 0xFF;
            kek[2] = (r1 >>> 8) & 0xFF;
            kek[3] = r1 & 0xFF;
            iv = new Uint8Array(crypto.AES_BLOCK_SIZE);
            iv[0] = (r2 >>> 24) & 0xFF;
            iv[1] = (r2 >>> 16) & 0xFF;
            iv[2] = (r2 >>> 8) & 0xFF;
            iv[3] = r2 & 0xFF;
            d = new Uint8Array(keyLength);
            var e = CryptoJS.AES.encrypt(CryptoJS.lib.WordArray.create(d), CryptoJS.lib.WordArray.create(kek),
		        { mode: CryptoJS.mode.CTR, padding: CryptoJS.pad.NoPadding, iv: CryptoJS.lib.WordArray.create(iv) });
            return e.ciphertext.toString(CryptoJS.enc.Base64);
        }
    });

    function wordArrayToUint8Array(wordArray) {
        var words = wordArray.words;
        var sigBytes = wordArray.sigBytes;
        var u8 = new Uint8Array(sigBytes);
        for (var i = 0; i < sigBytes; i++) {
            var vByte = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
            u8[i] = vByte;
        }
        return u8;
    }

    /**
     * @description a wrapper of CryptoJS
     * @namespace SrtpJS.crypto
     */

    exports.crypto = crypto;
})(SrtpJS, CryptoJS);
