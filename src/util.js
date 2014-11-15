/** 
* @fileOverview Utility implementation 
* @author <a href="jamol@live.com">Fengping Bao</a>
* @version 0.1 
*/
; (function (SrtpJS, undefined) {
    var exports = SrtpJS,
        util = exports.util || {}
    ;

    var maxUint32 = 4294967295,
        halfOfMaxUint32 = 2147483647,
        negativeHalfOfMaxUint32 = -2147483647
    ;

    SrtpJS.extend(util, {

        /**
         * @description Convert a string into an array of char codes
         * @function SrtpJS.util.stringToArray
         * @param {String} str the string to be converted to array
         * @returns {Array} the converted array
         */
        stringToArray: function (str) {
            if (typeof str != "string" || !str instanceof String) {return null;}
            var r = [];
            for (var i = 0; i < str.length; i++) {
                r.push(str.charCodeAt(i));
            }
            return r;
        },

        /**
         * @description Convert a string into an uint8array of char codes
         * @function SrtpJS.util.stringToUint8Array
         * @param {String} str the string to be converted to array
         * @returns {Uint8Array} the converted array
         */
        stringToUint8Array: function (str) {
            if (typeof str != "string" || !str instanceof String) { return null; }
            var r = new Uint8Array(str.length);
            for (var i = 0; i < str.length; i++) {
                r[i] = str.charCodeAt(i);
            }
            return r;
        },

        /**
         * @description Convert a binary array to string, pair to {@link SrtpJS.util.stringToArray}
         * @function SrtpJS.util.arrayToString
         * @param {Array} d the array to be converted to string
         * @returns {String} the converted string
         */
        arrayToString: function(d) {
            return String.fromCharCode.apply(String, d);
        },

        /**
         * @description Convert a HEX string to an uint8array
         * @function SrtpJS.util.hexStringToUint8Array
         * @param {String} hexStr the string to be converted
         * @returns {Uint8Array} the converted array
         */
        hexStringToUint8Array: function (hexStr) {
            var d = new Uint8Array(hexStr.length >>> 1);
            for (var i = 0, j = 0; i < hexStr.length; i += 2, ++j) {
                d[j] |= parseInt(hexStr.substr(i, 2), 16);
            }
            return d;
        },

        /**
         * @description Convert a uint8array to HEX string, pair to {@link SrtpJS.util.hexStringToUint8Array}
         * @function SrtpJS.util.uint8ArrayToHexString
         * @param {Uint8Array} d the uint8array to be converted
         * @returns {String} the converted HEX string
         */
        uint8ArrayToHexString: function (d) {
            var s = [];
            for (var i = 0; i < d.length; ++i) {
                s.push(d[i].toString(16));
            }
            return s.join('');
        },

        calcDiffUint16: function (u1, u2) {
            var diff
            ;
            diff = u1 - u2;
            if (diff > 32767) {
                diff = diff - 65536;
            }
            else if (diff < -32767) {
                diff = 65536 + diff;
            }
            return diff;
        },

        calcDiffUint32: function (u1 , u2) {
            var diff
            ;
            diff = u1 - u2;
            if (diff > halfOfMaxUint32) {
                diff = diff - maxUint32 - 1;
            }
            else if (diff < negativeHalfOfMaxUint32) {
                diff = maxUint32 + 1 + diff;
            }
            return diff;
        },

        incUint32: function (v) {
            if (++v > maxUint32) {
                return 0;
            } else {
                return v;
            }
        },

        decUint32: function (v) {
            if (--v < 0) {
                return maxUint32;
            } else {
                return v;
            }
        },

        arrayEqual: function (a1, a2) {
            if (a1.length != a2.length) {
                return false;
            }
            for (var i = 0; i < a1.length; ++i) {
                if (a1[i] != a2[i]) {
                    return false;
                }
            }
            return true;
        }
    });

    /**
     * @description namespace of SrtpJS.util
     * @namespace SrtpJS.util
     */

    exports.util = util;
    return util;
})(SrtpJS);