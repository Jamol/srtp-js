; (function (SrtpJS, undefined) {
    var logger = SrtpJS.logger,
        util = SrtpJS.util,
        crypto = SrtpJS.crypto
    ;

    var key = new Uint8Array([0xE1, 0xF9, 0x7A, 0x0D, 0x3E, 0x01, 0x8B, 0xE0, 0xD6, 0x4F, 0xA3, 0x2C, 0x06, 0xDE, 0x41, 0x39]),
        iv = new Uint8Array([0x0E, 0xC6, 0x75, 0xAD, 0x49, 0x8A, 0xFE, 0xEB, 0xB6, 0x96, 0x0B, 0x3A, 0xAB, 0xE6, 0x00, 0x00]),
        data = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        cipher = new Uint8Array([0xC6, 0x1E, 0x7A, 0x93, 0x74, 0x4F, 0x39, 0xEE, 0x10, 0x73, 0x4A, 0xFE, 0x3F, 0xF7, 0xA0, 0x87])
    ;

    test("test aesCtrEncrypt", function () {
        var e = crypto.aesCtrEncrypt(data, key, iv);
        equal(e.length, cipher.length, "verify data length");
        var verifyData = true;
        for (var i = 0; i < e.length; ++i) {
            if (e[i] != cipher[i]) {
                verifyData = false;
                break;
            }
        }
        ok(verifyData, "verify data");
    });

    test("test aesCtrDecrypt", function () {
        var d = crypto.aesCtrEncrypt(cipher, key, iv);
        equal(d.length, data.length, "verify data length");
        var verifyData = true;
        for (var i = 0; i < d.length; ++i) {
            if (d[i] != data[i]) {
                verifyData = false;
                break;
            }
        }
        ok(verifyData, "verify data");
    });

    test("test aesEcbEncrypt", function () {
        var e = crypto.aesEcbEncrypt(data, key);
        ok(e != null, "verify data");
        ok(e.length > 0, "verify data length");
    });

    test("test aesEcbEncrypt -- 2", function () {
        var d = new Uint8Array([0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        var k = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F]);
        var e = crypto.aesEcbEncrypt(d, k);
        logger.info(e);
        ok(e != null, "verify data");
        ok(e.length > 0, "verify data length");
    });

    test("test aesEcbDecrypt", function () {
        var e = crypto.aesEcbEncrypt(iv, key);
        var d = crypto.aesEcbDecrypt(e, key);
        equal(d.length, iv.length, "verify data length");
        var verifyData = true;
        for (var i = 0; i < d.length; ++i) {
            if (d[i] != iv[i]) {
                verifyData = false;
                break;
            }
        }
        ok(verifyData, "verify data");
    });

    test("test hmacSha1", function () {
        var h = crypto.hmacSha1(iv, key);
        ok(h != null, "verify hash");
        equal(20, h.length, "verify hash length");
    });

    test("test hmacSha1List", function () {
        var h = crypto.hmacSha1List([iv], key);
        ok(h != null, "verify hash");
        equal(20, h.length, "verify hash length");
        var h2 = crypto.hmacSha1(iv, key);
        ok(util.arrayEqual(h, h2), "verify hash1 and hash2");
    });

    test("test generateKey", function () {
        var key = crypto.generateKey(16);
        ok(key != null, "verify key");
        equal(16, key.length, "verify key length");
    });

    test("test generateKeyBase64", function () {
        var key = crypto.generateKeyBase64(16);
        ok(key != null, "verify key");
    });

})(SrtpJS);
