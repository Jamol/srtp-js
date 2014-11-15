/** 
* @fileOverview SRTP-EKT implementation 
* @author <a href="jamol@live.com">Fengping Bao</a>
* @version 0.1 
*/
; (function (SrtpJS, undefined) {
    var exports = SrtpJS,
        logger = SrtpJS.logger,
        defs = SrtpJS.defs,
        crypto = SrtpJS.crypto,
        srtp = SrtpJS.srtp || {}
    ;

    var AESKW_BLOCK_SIZE = 8;

    function ektEncode(o, ektKey) {
        var plainText,
            cipherText,
            outData,
            spi
        ;
        if (defs.ektType.EKT_TYPE_SHORT == o.type) {
            outData = new Uint8Array(o.data.length + 1);
            outData.set(o.data);
            outData[outData.length - 1] = 0;
            return outData;
        }
        // full EKT field
        plainText = new Uint8Array(o.masterKey.length + 10);
        plainText.set(o.masterKey, 0);
        plainText[o.masterKey.length] = (o.ssrc >>> 24) & 0xFF;
        plainText[o.masterKey.length + 1] = (o.ssrc >>> 16) & 0xFF;
        plainText[o.masterKey.length + 2] = (o.ssrc >>> 8) & 0xFF;
        plainText[o.masterKey.length + 3] = o.ssrc & 0xFF;
        plainText[o.masterKey.length + 4] = (o.roc >>> 24) & 0xFF;
        plainText[o.masterKey.length + 5] = (o.roc >>> 16) & 0xFF;
        plainText[o.masterKey.length + 6] = (o.roc >>> 8) & 0xFF;
        plainText[o.masterKey.length + 7] = o.roc & 0xFF;
        plainText[o.masterKey.length + 8] = (o.isn >>> 8) & 0xFF;
        plainText[o.masterKey.length + 9] = o.isn & 0xFF;

        cipherText = aeskwWrap(plainText, ektKey);
        spi = o.spi;
        spi = spi << 1;
        spi = spi | 0x01;
        outData = new Uint8Array(o.data.length + cipherText.length + 2);
        outData.set(o.data);
        outData.set(cipherText, o.data.length);
        outData[outData.length - 2] = (spi >>> 8) & 0xFF;
        outData[outData.length - 1] = spi & 0xFF;
        return outData;
    }

    function ektDecode(data, ektKey) {
        var spi,
            cipherText,
            plainText,
            m, r, o
        ;
        if (data.length <= 2) {
            logger.error("[EKT] ektDecode, invlaid data length: " + data.length);
            return { type: defs.ektType.EKT_TYPE_NULL, desc: "invalid data" };
        }
        if ((data[data.length - 1] & 0x01) == 0) {
            return { type: defs.ektType.EKT_TYPE_SHORT, data: data.subarray(0, data.length - 1) };
        }
        spi = ((data[data.length - 2] & 0xFF) << 8) | (data[data.length - 1] & 0xFF);
        spi = spi >>> 1;
        // TODO: calculate m based on SPI
        m = 16 + 4 + 4 + 2;
        r = (m + 8 + 7) & 0xFFFFFFF8;
        if (data.length < r + 2) {
            logger.error("[EKT] ektDecode, the length is incorrect, length=" + data.length + ", r=" + r);
            return { type: defs.ektType.EKT_TYPE_NULL, desc: "invalid data" };
        }
        cipherText = data.subarray(data.length - r - 2, data.length - 2);
        plainText = aeskwUnwrap(cipherText, ektKey);
        if (null == plainText) {
            return { type: defs.ektType.EKT_TYPE_NULL, desc: "failed to unwrap the key" };
        }
        if (plainText.length != m) {
            logger.error("[EKT] ektDecode, the length is incorrect, length=" + plainText.length + ", m=" + m);
            return { type: defs.ektType.EKT_TYPE_NULL, desc: "invalid data" };
        }
        o = {};
        o.type = defs.ektType.EKT_TYPE_FULL;
        o.isn = ((plainText[plainText.length - 2] & 0xFF) << 8) | (plainText[plainText.length - 1] & 0xFF);
        o.roc = plainText[plainText.length - 3] & 0xFF;
        o.roc |= (plainText[plainText.length - 4] & 0xFF << 8);
        o.roc |= (plainText[plainText.length - 5] & 0xFF << 16);
        o.roc |= (plainText[plainText.length - 6] & 0xFF << 24);
        o.ssrc = plainText[plainText.length - 7] & 0xFF;
        o.ssrc |= (plainText[plainText.length - 8] & 0xFF << 8);
        o.ssrc |= (plainText[plainText.length - 9] & 0xFF << 16);
        o.ssrc |= (plainText[plainText.length - 10] & 0xFF << 24);
        o.masterKey = plainText.subarray(0, plainText.length - 10);
        o.data = data.subarray(0, data.length - r - 2);
        return o;
    }

    function aeskwWrap(data, key) {
        var dataLength,
            m, n, r, A, B, R, S, t, i, j
        ;
        m = data.length;
        n = Math.ceil(m / AESKW_BLOCK_SIZE);
        r = n * AESKW_BLOCK_SIZE;
        if (r > m) {
            var d1 = new Uint8Array(r);
            d1.set(data);
            for (i = 0; i < r - m; ++i) {
                d1[m + i] = 0;
            }
            data = d1;
        }
        A = new Uint8Array(AESKW_BLOCK_SIZE);
        A.set([0xA6, 0x59, 0x59, 0xA6]);
        A[4] = (m >>> 24) & 0xFF;
        A[5] = (m >>> 16) & 0xFF;
        A[6] = (m >>> 8) & 0xFF;
        A[7] = m & 0xFF;
        S = new Uint8Array(2 * AESKW_BLOCK_SIZE);

        if (1 == n) {
            S.set(A);
            S.set(data, AESKW_BLOCK_SIZE);
            B = crypto.aesEcbEncrypt(S, key);
            return B;
        }

        R = new Uint8Array(r + AESKW_BLOCK_SIZE);
        R.set(A);
        R.set(data, AESKW_BLOCK_SIZE);
        A = R.subarray(0, 8);
        for (j = 0; j < 6; ++j) {
            for (i = 1; i < n + 1; ++i) {
                S.set(A);
                S.set(R.subarray(8 * i, 8 * i + 8), 8);
                B = crypto.aesEcbEncrypt(S, key);
                A.set(B.subarray(0, 8));
                t = n * j + i;
                A[4] = A[4] ^ ((t >>> 24) & 0xFF);
                A[5] = A[5] ^ ((t >>> 16) & 0xFF);
                A[6] = A[6] ^ ((t >>> 8) & 0xFF);
                A[7] = A[7] ^ (t & 0xFF);
                R.set(B.subarray(8, 16), 8 * i);
            }
        }
        return R;
    }

    function aeskwUnwrap(data, key) {
        var m, n, P, A, B, S, padded, r, t, i, j;
        m = data.length;
        if (m < 2 * AESKW_BLOCK_SIZE) {
            logger.error("[EKT] aeskwUnwrap, invalid data length, m=" + m);
            return null;
        }
        n = Math.ceil(m / AESKW_BLOCK_SIZE);
        r = n * AESKW_BLOCK_SIZE;
        --n;
        if (r != m) {
            logger.error("[EKT] aeskwUnwrap, invalid data, r=" + r + ", m=" + m);
            return null; // invalid data
        }
        if (1 == n) {
            B = crypto.aesEcbDecrypt(data, key);
            A = B.subarray(0, 8);
            P = B.subarray(8, 16);
        } else {
            P = new Uint8Array(r);
            P.set(data.subarray(0, r));
            A = P.subarray(0, 8);
            S = new Uint8Array(2 * AESKW_BLOCK_SIZE);
            for (j = 5; j >= 0; --j) {
                for (i = n; i >= 1; --i) {
                    t = n * j + i;
                    A[4] = A[4] ^ ((t >>> 24) & 0xFF);
                    A[5] = A[5] ^ ((t >>> 16) & 0xFF);
                    A[6] = A[6] ^ ((t >>> 8) & 0xFF);
                    A[7] = A[7] ^ (t & 0xFF);
                    S.set(A);
                    S.set(P.subarray(8 * i, 8 * i + 8), 8);
                    B = crypto.aesEcbDecrypt(S, key);
                    A.set(B.subarray(0, 8));
                    P.set(B.subarray(8, 16), 8 * i);
                }
            }
            P = P.subarray(8, r); // remove the A
        }
        if (A[0] != 0xA6 || A[1] != 0x59 || A[2] != 0x59 || A[3] != 0xA6) {
            logger.error("[EKT] aeskwUnwrap, failed to authenticate A: ", A);
            return null;
        }
        var l = (A[4] << 24) | (A[5] << 16) | (A[6] << 8) | A[7];
        if (l > 8 * n || l <= 8 * (n - 1)) {
            logger.error("[EKT] aeskwUnwrap, failed to authenticate length, l=" + l);
            return null;
        }
        var b = 8*n - l;
        if (b > 0) {
            for (i = 0; i < b; ++i) {
                if (P[l + i] != 0) {
                    logger.error("[EKT] aeskwUnwrap, failed to authenticate padding data");
                    return null;
                }
            }
            P = P.subarray(0, l);
        }
        return P;
    }

    srtp.ektEncode = ektEncode;
    srtp.ektDecode = ektDecode;
    exports.srtp = srtp;
    return srtp;
})(SrtpJS);
