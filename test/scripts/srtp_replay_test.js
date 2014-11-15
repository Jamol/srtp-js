; (function (SrtpJS, undefined) {
    var logger = SrtpJS.logger,
        util = SrtpJS.util,
        defs = SrtpJS.defs,
        srtp = SrtpJS.srtp
    ;

    test("test ReplayItem -- normal index", function () {
        logger.info("test ReplayItem -- normal index");
        var replayItem = new srtp.ReplayItem();
        var index = 8;
        var rv = replayItem.checkIndex(index);
        ok(rv, "first index: 8");
        replayItem.updateIndex(index);
        index = 9;
        var rv = replayItem.checkIndex(index);
        ok(rv, "index: 9");
        replayItem.updateIndex(index);
        index = 9 + 255;
        var rv = replayItem.checkIndex(index);
        ok(rv, "index: " + index);
        replayItem.updateIndex(index);
        index = 9 + 256;
        var rv = replayItem.checkIndex(index);
        ok(rv, "index: " + index);
        replayItem.updateIndex(index);
    });

    test("test ReplayItem -- normal index", function () {
        logger.info("test ReplayItem -- normal index");
        var replayItem = new srtp.ReplayItem();
        var index = 8;
        var startIndex = index;
        var rv;
        for (var i = 0; i < 256; ++i, ++index) {
            rv = replayItem.checkIndex(index);
            ok(rv, "index: " + index);
            replayItem.updateIndex(index);
        }
        index = startIndex;
        for (var i = 0; i < 256; ++i, ++index) {
            rv = replayItem.checkIndex(index);
            ok(!rv, "index: " + index);
            //replayItem.updateIndex(index);
        }
    });

    test("test ReplayItem -- disorder index", function () {
        logger.info("test ReplayItem -- normal index");
        var replayItem = new srtp.ReplayItem();
        var index = 9;
        var rv = replayItem.checkIndex(index);
        ok(rv, "first index: " + index);
        replayItem.updateIndex(index);
        index = 8;
        var rv = replayItem.checkIndex(index);
        ok(rv, "index: " + index);
        replayItem.updateIndex(index);
        index = 9 + 256;
        var rv = replayItem.checkIndex(index);
        ok(rv, "index: " + index);
        replayItem.updateIndex(index);
        index = 9 + 254;
        var rv = replayItem.checkIndex(index);
        ok(rv, "index: " + index);
        replayItem.updateIndex(index);
    });

    test("test ReplayItem -- large index", function () {
        logger.info("test ReplayItem -- normal index");
        var replayItem = new srtp.ReplayItem();
        var index = 8;
        var rv = replayItem.checkIndex(index);
        ok(rv, "first index: 8");
        replayItem.updateIndex(index);
        index = 9;
        var rv = replayItem.checkIndex(index);
        ok(rv, "index: 9");
        replayItem.updateIndex(index);
        index = 9 + 257;
        var rv = replayItem.checkIndex(index);
        ok(!rv, "index: " + index);
        replayItem.updateIndex(index);
    });

    test("test ReplayItem -- same index", function () {
        logger.info("test ReplayItem -- normal index");
        var replayItem = new srtp.ReplayItem();
        var index = 8;
        var rv = replayItem.checkIndex(index);
        ok(rv, "first index: 8");
        replayItem.updateIndex(index);
        index = 9;
        var rv = replayItem.checkIndex(index);
        ok(rv, "index: 9");
        replayItem.updateIndex(index);
        index = 9;
        var rv = replayItem.checkIndex(index);
        ok(!rv, "index: " + index);
        replayItem.updateIndex(index);
        index = 8;
        var rv = replayItem.checkIndex(index);
        ok(!rv, "index: " + index);
        replayItem.updateIndex(index);
    });

    test("test ReplayItem -- small index", function () {
        logger.info("test ReplayItem -- normal index");
        var replayItem = new srtp.ReplayItem();
        var index = 357;
        var rv = replayItem.checkIndex(index);
        ok(rv, "first index: " + index);
        replayItem.updateIndex(index);
        index = 353;
        var rv = replayItem.checkIndex(index);
        ok(rv, "index: " + index);
        replayItem.updateIndex(index);
        index = 353 - 257;
        var rv = replayItem.checkIndex(index);
        ok(!rv, "index: " + index);
        replayItem.updateIndex(index);
    });

})(SrtpJS);