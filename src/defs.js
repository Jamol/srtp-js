/**
 * @fileOverview definition
 * @author <a href="jamol@live.com">Fengping Bao</a>
 * @version 0.1
 */
; (function (SrtpJS, undefined) {
    var exports = SrtpJS,
        defs = exports.defs || {},
        moduleId = 12,
        errBase = (2 << 23)|(moduleId << 15);

    SrtpJS.extend(defs, {
        /**
         * @description the SRTP crypto suites
         * @namespace SrtpJS.defs.srtpCryptoSuite
         */
        srtpCryptoSuite: {
            /** @constant SrtpJS.defs.srtpCryptoSuite.NULL_CIPHER_HMAC_SHA1_80 */
            NULL_CIPHER_HMAC_SHA1_80: 1,
            /** @constant SrtpJS.defs.srtpCryptoSuite.AES_CM_128_HMAC_SHA1_80 */
            AES_CM_128_HMAC_SHA1_80: 2, // RFC3711
        },

        srtpCipherType: {
            NULL_CIPHER: 0,
            AES_CM_128: 1
        },

        srtpAuthType: {
            HAMC_SHA1: 0,
        },

        srtpAuthTagType: {
            RFC3711: 0,
            OSW: 1
        },
        
        ektType: {
            EKT_TYPE_NULL: 0,
            EKT_TYPE_SHORT: 1,
            EKT_TYPE_FULL: 2
        },

        /**
         * @description the EKT cipher type
         * @namespace SrtpJS.defs.ektCipherType
         */
        ektCipherType: {
            /** @constant SrtpJS.defs.ektCipherType.AESKW_128 */
            AESKW_128: 0
        }
    });

    /**
     * @description namespace of SrtpJS.defs
     * @namespace SrtpJS.defs
     */
    exports.defs = defs;
    return defs;
})(SrtpJS);