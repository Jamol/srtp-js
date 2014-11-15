; (function (SrtpJS, undefined) {
    var logger = SrtpJS.logger,
        util = SrtpJS.util,
        defs = SrtpJS.defs,
        srtp = SrtpJS.srtp,
        crypto = SrtpJS.crypto
    ;

    var masterKey = new Uint8Array([0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41, 0x39]),
        masterSalt = new Uint8Array([0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6]),
        ektKey = new Uint8Array([0x39, 0x41, 0xDE, 0x06, 0x2C, 0xA3, 0x4F, 0xD6, 0xE0, 0x8B, 0x01, 0x3E, 0x0D, 0x7A, 0xF9, 0xE1])
    ;

    var null_auth_cipher_text_hex = "800f1234decafbaddecafbad8048e56a01cdf0fe0d787818c1ca1ccae7d5270e82bd2769275a8388d91dadef1392f226a9ffb21fc904378155288cee8d5891013d5983b47792dd63bb12c32f1f66725faf2092dae8228d074471c484";

    var packet_protected_hex = "800f1234decafbaddecafbad8048e56a01cdf0fe0d787818c1ca1ccae7d5270e82bd2769275a8388d91dadef1392f226a9ffb21fc904378155288cee8d5891013d5983b47792dd63bb12c32f1f66725faf2092dae8228d074471c484d71fe14c11b4f74b8f82";
   
   var compound_rtcp_packet_hex = "82c90d5add9a75811b9959018b507f5fe7029b9121b981bb0011d4aa997e7b0fa8a0274153005b9e15ae0bb0016782ca0c0035b1848656c6c6f35323827526f6f6d37393100060681848656c6c6f35323827526f6f6d3739310";

    var ssrc = 95279527,
        srInfo = { ntph: 234254, ntpl: 831892, ts: 585735, count: 3456, bytes: 343653 },
        rrBlock1 = { ssrc: 92347289, flost: 89, plost: 6325, xseq: 8347623, jitter: 2734354, lsr: 28934587, dlsr: 285 },
        rrBlock2 = { ssrc: 78289278, flost: 123, plost: 64138, xseq: 2572627, jitter: 23454, lsr: 22732987, dlsr: 359 },
        sdesTrunk1 = { ssrc: 13579, sdesItems: [{ type: 1, content: [72, 101, 108, 108, 111, 53, 50, 56] }, { type: 2, content: [82, 111, 111, 109, 55, 57, 49] }] },
        sdesTrunk2 = { ssrc: 24680, sdesItems: [{ type: 1, content: [72, 101, 108, 108, 111, 53, 50, 56] }, { type: 2, content: [82, 111, 111, 109, 55, 57, 49] }] }
    ;

    test("test generateIV -- non salt", function () {
        var seq = 23845;
        var roc = 0;
        var iv = srtp.generateIV(ssrc, seq, roc);
        ok(iv != null, "check IV");
        var i = 1;
        equal(iv[iv.length - 2 - i], (seq & 0xFF), "check IV value");
        ++i;
        equal(iv[iv.length - 2 - i], ((seq >>> 8) & 0xFF), "check IV value");
        ++i
        // ROC
        equal(iv[iv.length - 2 - i], (roc & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], ((roc >>> 8) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], ((roc >>> 16) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], ((roc >>> 24) & 0xFF), "check IV value");
        ++i
        // SSRC
        equal(iv[iv.length - 2 - i], (ssrc & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], ((ssrc >>> 8) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], ((ssrc >>> 16) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], ((ssrc >>> 24) & 0xFF), "check IV value");
    });

    test("test generateIV -- has salt", function () {
        var seq = 23845;
        var roc = 0;
        var salt = new Uint8Array([82, 34, 89, 56, 12, 34, 56, 78, 123, 254, 248, 159, 92, 197]);
        var iv = srtp.generateIV(ssrc, seq, roc, salt);
        ok(iv != null, "check IV");
        var i = 1;
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ (seq & 0xFF), "check IV value");
        ++i;
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((seq >>> 8) & 0xFF), "check IV value");
        ++i
        // ROC
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ (roc & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((roc >>> 8) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((roc >>> 16) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((roc >>> 24) & 0xFF), "check IV value");
        ++i
        // SSRC
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ (ssrc & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((ssrc >>> 8) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((ssrc >>> 16) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((ssrc >>> 24) & 0xFF), "check IV value");
    });

    test("test generateIV -- has roc", function () {
        var seq = 23845;
        var roc = 3;
        var salt = new Uint8Array([82, 34, 89, 56, 12, 34, 56, 78, 123, 254, 248, 159, 92, 197]);
        var iv = srtp.generateIV(ssrc, seq, roc, salt);
        ok(iv != null, "check IV");
        var i = 1;
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ (seq & 0xFF), "check IV value");
        ++i;
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((seq >>> 8) & 0xFF), "check IV value");
        ++i
        // ROC
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ (roc & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((roc >>> 8) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((roc >>> 16) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((roc >>> 24) & 0xFF), "check IV value");
        ++i
        // SSRC
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ (ssrc & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((ssrc >>> 8) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((ssrc >>> 16) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((ssrc >>> 24) & 0xFF), "check IV value");
    });

    test("test generateIVRTCP -- non salt", function () {
        var index = 238457;
        var iv = srtp.generateIVRTCP(ssrc, index);
        ok(iv != null, "check IV");
        var i = 1;
        // index
        equal(iv[iv.length - 2 - i], (index & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], ((index >>> 8) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], ((index >>> 16) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], ((index >>> 24) & 0xFF), "check IV value");
        ++i
        // 
        equal(iv[iv.length - 2 - i], 0, "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], 0, "check IV value");
        ++i
        // SSRC
        equal(iv[iv.length - 2 - i], (ssrc & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], ((ssrc >>> 8) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], ((ssrc >>> 16) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], ((ssrc >>> 24) & 0xFF), "check IV value");
    });

    test("test generateIVRTCP -- has salt", function () {
        var index = 238457;
        var salt = new Uint8Array([82, 34, 89, 56, 12, 34, 56, 78, 123, 254, 248, 159, 92, 197]);
        var iv = srtp.generateIVRTCP(ssrc, index, salt);
        ok(iv != null, "check IV");
        var i = 1;
        // index
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ (index & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((index >>> 8) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((index >>> 16) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((index >>> 24) & 0xFF), "check IV value");
        ++i
        // 
        equal(iv[iv.length - 2 - i], salt[salt.length - i], "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i], "check IV value");
        ++i
        // SSRC
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ (ssrc & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((ssrc >>> 8) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((ssrc >>> 16) & 0xFF), "check IV value");
        ++i
        equal(iv[iv.length - 2 - i], salt[salt.length - i] ^ ((ssrc >>> 24) & 0xFF), "check IV value");
    });

    test("test generateKey -- key derivation rate is 0", function () {
        var seq = 23845;
        var roc = 3;
        var key = srtp.generateKey(seq, roc, 0, 0, 16, masterKey, masterSalt, crypto.aesCtrEncrypt);
        ok(key != null, "check key");
    });

    test("test generateKey -- key derivation rate is non-zero", function () {
        var seq = 23845;
        var roc = 3;
        var key = srtp.generateKey(seq, roc, 1024, 0, 16, masterKey, masterSalt, crypto.aesCtrEncrypt);
        ok(key != null, "check key");
    });

    test("test generateKeyRTCP -- key derivation rate is 0", function () {
        var index = 2384523;
        var key = srtp.generateKeyRTCP(index, 0, 0, 16, masterKey, masterSalt, crypto.aesCtrEncrypt);
        ok(key != null, "check key");
    });

    test("test generateKeyRTCP -- key derivation rate is non-zero", function () {
        var index = 2384523;
        var key = srtp.generateKeyRTCP(index, 65536, 0, 16, masterKey, masterSalt, crypto.aesCtrEncrypt);
        ok(key != null, "check key");
    });

    ///////////////////////////////////////////////////////////////////////
    test("test RTPCryptoContext -- authenticate failed (RFC3711)", function () {
        var ssrc = 0xA7834F9B;
        var options = {
            masterKey: masterKey,
            masterSaltKey: masterSalt,
            hasMKI: false,
            keyDrvRate: 0,
            cryptoSuite: defs.srtpCryptoSuite.NULL_CIPHER_HMAC_SHA1_80,
            //ektOptions: {},
        };
        var ctx = new srtp.RTPCryptoContext(ssrc, options);
        var data = new Uint8Array(32 + 1024);
        data[0] = 0x91;
        data[1] = 0x63;
        data[2] = 0x70;
        data[3] = 0x0b;
        data[4] = 0x00;
        data[5] = 0xab;
        data[6] = 0x41;
        data[7] = 0x30;
        data[8] = 0x00;
        data[9] = 0x0e;
        data[10] = 0x27;
        data[11] = 0x29;
        data[12] = 0x00;
        data[13] = 0x00;
        data[14] = 0x33;
        data[15] = 0xa7;
        data[16] = 0xbe;
        data[17] = 0xde;
        data[18] = 0x00;
        data[19] = 0x03;
        data[20] = 0x12;
        data[21] = 0x02;
        data[22] = 0x08;
        data[23] = 0x20;
        data[24] = 0x22;
        data[25] = 0x00;
        data[26] = 0x95;
        data[27] = 0xc4;
        data[28] = 0x30;
        data[29] = 0x04;
        data[30] = 0x00;
        data[31] = 0x00;
        for (var i = 0; i < 1024; ++i) {
            data[32 + i] = i;
        }

        var d = ctx.unprotect(data);
        ok(d == null, "test unprotect");
    });

    test("test RTPCryptoContext -- authenticate successfully (RFC3711)", function () {
        var data = util.hexStringToUint8Array(packet_protected_hex);
        var ssrc = data[8] << 24 | data[9] << 16 | data[10] << 8 | data[11];
        var options = {
            masterKey: masterKey,
            masterSaltKey: masterSalt,
            hasMKI: false,
            keyDrvRate: 0,
            cryptoSuite: defs.srtpCryptoSuite.AES_CM_128_HMAC_SHA1_80
        };
        var ctx = new srtp.RTPCryptoContext(ssrc, options);

        var d = ctx.unprotect(data);
        ok(d != null, "test unprotect");
        equal(d.length, data.length - 10, "verify data length");
    });
   
    /////////////////////////////////////////////////////////////
    test("test RTCPCryptoContext -- test protect (NULL_CIPHER)", function () {
        var options = {
            masterKey: masterKey,
            masterSaltKey: masterSalt,
            hasMKI: false,
            keyDrvRate: 0,
            cryptoSuite: defs.srtpCryptoSuite.NULL_CIPHER_HMAC_SHA1_80
            //ektOptions: {},
        };
        var ctx = new srtp.RTCPCryptoContext(ssrc, options);
        var data = util.hexStringToUint8Array(compound_rtcp_packet_hex);

        var tagLength = 10;
        var d = ctx.protect(data);
        ok(d != null, "test protect");
        equal(d.length, data.length + tagLength + 4, "check protected data length");
    });

    test("test RTCPCryptoContext -- test unprotect (NULL_CIPHER)", function () {
        var options = {
            masterKey: masterKey,
            masterSaltKey: masterSalt,
            hasMKI: false,
            keyDrvRate: 0,
            cryptoSuite: defs.srtpCryptoSuite.NULL_CIPHER_HMAC_SHA1_80
            //ektOptions: {},
        };
        var ctx = new srtp.RTCPCryptoContext(ssrc, options);
        var data = util.hexStringToUint8Array(compound_rtcp_packet_hex);

        var tagLength = 10;
        var d = ctx.protect(data);
        ok(d != null, "test protect");
        equal(d.length, data.length + tagLength + 4, "check protected data length");

        var ctx1 = new srtp.RTCPCryptoContext(ssrc, options);
        var d2 = ctx1.unprotect(d);
        equal(d2.length, data.length, "check unprotected data length");
        var verifyData = true;
        for (var i = 0; i < data.length; ++i) {
            if (data[i] != d2[i]) {
                verifyData = false;
                break;
            }
        }
        ok(verifyData, "verify data");
    });

    test("test RTCPCryptoContext -- test protect (AES_CM)", function () {
        var options = {
            masterKey: masterKey,
            masterSaltKey: masterSalt,
            hasMKI: false,
            keyDrvRate: 0,
            cryptoSuite: defs.srtpCryptoSuite.AES_CM_128_HMAC_SHA1_80
            //ektOptions: {},
        };
        var ctx = new srtp.RTCPCryptoContext(ssrc, options);
        var data = util.hexStringToUint8Array(compound_rtcp_packet_hex);

        var tagLength = 10;
        var d = ctx.protect(data);
        ok(d != null, "test protect");
        equal(d.length, data.length + tagLength + 4, "check protected data length");
    });

    test("test RTCPCryptoContext -- test unprotect (AES_CM)", function () {
        var options = {
            masterKey: masterKey,
            masterSaltKey: masterSalt,
            hasMKI: false,
            keyDrvRate: 0,
            cryptoSuite: defs.srtpCryptoSuite.AES_CM_128_HMAC_SHA1_80
            //ektOptions: {},
        };
        var ctx = new srtp.RTCPCryptoContext(ssrc, options);
        var data = util.hexStringToUint8Array(compound_rtcp_packet_hex);

        var tagLength = 10;
        var d = ctx.protect(data);
        ok(d != null, "test protect");
        equal(d.length, data.length + tagLength + 4, "check protected data length");

        var ctx1 = new srtp.RTCPCryptoContext(ssrc, options);
        var d2 = ctx1.unprotect(d);
        equal(d2.length, data.length, "check unprotected data length");
        var verifyData = true;
        for (var i = 0; i < data.length; ++i) {
            if (data[i] != d2[i]) {
                verifyData = false;
                break;
            }
        }
        ok(verifyData, "verify data");
    });

    test("test RTCPCryptoContext -- test protect (AES_CM + EKT)", function () {
        var options = {
            masterKey: masterKey,
            masterSaltKey: masterSalt,
            hasMKI: false,
            keyDrvRate: 0,
            cryptoSuite: defs.srtpCryptoSuite.AES_CM_128_HMAC_SHA1_80,
            ektParams: {
                cipher: defs.ektCipherType.AESKW_128,
                key: ektKey,
                spi: 0
            }
        };
        var ctx = new srtp.RTCPCryptoContext(ssrc, options);
        var data = util.hexStringToUint8Array(compound_rtcp_packet_hex);

        var tagLength = 10;
        var d = ctx.protect(data);
        // TODO: send EKT full type packet
        //var ektLength = 42;
        var ektLength = 1;
        ok(d != null, "test protect");
        equal(d.length, data.length + tagLength + 4 + ektLength, "check protected data length");
    });

    test("test RTCPCryptoContext -- test unprotect (AES_CM + EKT)", function () {
        var options = {
            masterKey: masterKey,
            masterSaltKey: masterSalt,
            hasMKI: false,
            keyDrvRate: 0,
            cryptoSuite: defs.srtpCryptoSuite.AES_CM_128_HMAC_SHA1_80,
            ektParams: {
                cipher: defs.ektCipherType.AESKW_128,
                key: ektKey,
                spi: 0
            }
        };
        var ctx = new srtp.RTCPCryptoContext(ssrc, options);
        var data = util.hexStringToUint8Array(compound_rtcp_packet_hex);

        var tagLength = 10;
        var d = ctx.protect(data);
        // TODO: send EKT full type packet
        //var ektLength = 42;
        var ektLength = 1;
        ok(d != null, "test protect");
        equal(d.length, data.length + tagLength + 4 + ektLength, "check protected data length");

        var ctx1 = new srtp.RTCPCryptoContext(ssrc, options);
        var d2 = ctx1.unprotect(d);
        ok(d2 != null, "test unprotect");
        equal(d2.length, data.length, "check unprotected data length");
        var verifyData = true;
        for (var i = 0; i < data.length; ++i) {
            if (data[i] != d2[i]) {
                verifyData = false;
                break;
            }
        }
        ok(verifyData, "verify data");
    });

})(SrtpJS);