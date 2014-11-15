; (function (SrtpJS, undefined) {
    var logger = SrtpJS.logger,
        util = SrtpJS.util,
        defs = SrtpJS.defs,
        srtp = SrtpJS.srtp
    ;

    var ektKey = new Uint8Array([22, 71, 117, 195, 46, 111, 194, 25, 7, 48, 12, 123, 101, 162, 71, 19]),
        masterKey = new Uint8Array([82, 34, 89, 56, 12, 34, 56, 78, 123, 254, 248, 159, 92, 197, 94, 237]),
        ssrc = 95279527,
        testData = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0])
    ;

    test("test EKT encode -- short EKT field", function () {
        var o = {}, enData;
        o.type = defs.ektType.EKT_TYPE_SHORT;
        o.data = testData;
        enData = srtp.ektEncode(o, ektKey);
        ok(enData != null, "check EKT encode output");
        equal(enData.length, testData.length + 1, "check length");
        equal(enData[enData.length - 1], 0, "check EKT encode output");
    });

    test("test EKT encode -- full EKT field", function () {
        var o = {}, enData;
        o.type = defs.ektType.EKT_TYPE_FULL;
        o.masterKey = masterKey;
        o.ssrc = ssrc;
        o.roc = 2;
        o.isn = 32745;
        o.spi = 8;
        o.data = testData;
        enData = srtp.ektEncode(o, ektKey);
        ok(enData != null, "check EKT encode output");
        equal(enData.length, testData.length + Math.ceil((o.masterKey.length + 10 + 8)/8)*8 + 2, "check length");
        equal(enData[enData.length-1] & 0x01, 1, "check least bit of SPI");
    });

    test("test EKT decode -- short EKT field", function () {
        var o = {}, enData, deData;
        o.type = defs.ektType.EKT_TYPE_SHORT;
        o.data = testData;
        enData = srtp.ektEncode(o, ektKey);
        ok(enData != null, "check EKT encode output");
        equal(enData.length, testData.length + 1, "check length");
        equal(enData[enData.length - 1], 0, "check EKT encode output");

        o = srtp.ektDecode(enData, ektKey);
        equal(o.type, defs.ektType.EKT_TYPE_SHORT, "check EKT type");
        equal(o.data.length, testData.length, "check data length");
        var verifyData = true;
        for (var i = 0; i < o.data.length; ++i) {
            if (o.data[i] != testData[i]) {
                verifyData = false;
                break;
            }
        }
        ok(verifyData, "verify data");
    });

    test("test EKT decode -- full EKT field", function () {
        var o = {}, enData;
        o.type = defs.ektType.EKT_TYPE_FULL;
        o.masterKey = masterKey;
        o.ssrc = ssrc;
        o.roc = 2;
        o.isn = 32745;
        o.spi = 8;
        o.data = testData;
        enData = srtp.ektEncode(o, ektKey);
        ok(enData != null, "check EKT encode output");
        equal(enData.length, testData.length + Math.ceil((o.masterKey.length + 10 + 8) / 8) * 8 + 2, "check length");
        equal(enData[enData.length - 1] & 0x01, 1, "check least bit of SPI");

        o = srtp.ektDecode(enData, ektKey);
        equal(o.type, defs.ektType.EKT_TYPE_FULL, "check EKT type");
        equal(o.data.length, testData.length, "check data length");
        var verifyData = true;
        for (var i = 0; i < o.data.length; ++i) {
            if (o.data[i] != testData[i]) {
                verifyData = false;
                break;
            }
        }
        ok(verifyData, "verify data");
    });

    test("test EKT decode -- invalid data 1", function () {
        var o,
            data = new Uint8Array([1, 2])
        ;
        o = srtp.ektDecode(data, ektKey);
        equal(o.type, defs.ektType.EKT_TYPE_NULL, "check EKT type");
    });

    test("test EKT decode -- invalid data 2", function () {
        var o,
            data = new Uint8Array([22, 71, 117, 195, 46, 111, 194, 25, 7, 48, 12, 123, 101, 162, 71, 19,
                82, 34, 89, 56, 12, 34, 56, 78, 123, 254, 248, 159, 92, 197, 94, 237, 23, 35, 54, 3,
            195, 46, 111, 194, 25, 7, 48, 12, 123, 101, 162, 71, 19, 5])
        ;
        o = srtp.ektDecode(data, ektKey);
        equal(o.type, defs.ektType.EKT_TYPE_NULL, "check EKT type");
    });

})(SrtpJS);
