/** 
* @fileOverview SRTP implementation
* @author <a href="jamol@live.com">Fengping Bao</a>
* @version 0.1 
*/
; (function (SrtpJS, undefined) {
    var exports = SrtpJS,
        logger = SrtpJS.logger,
        util = SrtpJS.util,
        defs = SrtpJS.defs,
        crypto = SrtpJS.crypto,
        srtp = exports.srtp || {}
    ;

    // CONSTs
    var SRTP_WINDOW_SIZE = 64,
        LABEL_RTP_SESSION_KEY = 0,
        LABEL_RTP_AUTH_KEY = 1,
        LABEL_RTP_SESSION_SALT = 2,
        LABEL_RTCP_SESSION_KEY = 3,
        LABEL_RTCP_AUTH_KEY = 4,
        LABEL_RTCP_SESSION_SALT = 5,
        REPLAY_ITEM_SIZE = 256
    ;


    /**
     * @constructor CryptoContext
     * @description crypto context
     * @param {Integer} ssrc the SSRC
     * @param {Object} options the crypto context options
     * @param {Uint8Array} options.masterKey master key
     * @param {Uint8Array} options.masterSaltKey master salt key
     * @param {Integer} options.keyDrvRate key derivation rate
     * @param {Boolean} options.hasMKI indicate if MKI is enabled
     * @param {Integer} options.cipherParams the cipher parameters
     * @param {Integer} options.cipherParams.type the cipher type
     * @param {Integer} options.cipherParams.keyLength the length of session key
     * @param {Integer} options.cipherParams.saltLength the length of session salt key
     * @param {Integer} options.authParams the authenticate parameters
     * @param {Integer} options.authParams.type the authenticate type
     * @param {Integer} options.authParams.keyLength the length of authenticate key
     * @param {Integer} options.authParams.tagLength the length of authenticate tag
     * @param {Object} options.ektParams the EKT parameters if it is enabled
     * @param {SrtpJS.defs.ektCipherType} options.ektParams.cipher The EKT cipher used to encrypt the SRTP Master Key
     * @param {Uint8Array} options.ektParams.key The EKT key used to encrypt the SRTP Master Key
     * @param {Integer} options.ektParams.spi The EKT Security Parameter Index
     */
    function CryptoContext(ssrc, options) {
        this._init(ssrc, options);
    }

    SrtpJS.extend(CryptoContext.prototype, /** @lends CryptoContext.prototype*/{
        ssrc: 0,

        masterKey: null,    // Uint8Array
        masterSaltKey: null,    // Uint8Array
        hasMKI: false,
        packetCount: 0,         // counter of the number of SRTP packets that have been processed with the master key

        oldMasterKey: null,

        sessionKey: null,   // Uint8Array
        sessionKeyLength: 0,
        sessionSaltKey: null,   // Uint8Array
        sessionSaltKeyLength: 0,
        authKey: null,  // Uint8Array
        authKeyLength: 0,
        authTagLength: 0,
        keyDrvRate: 0,
        keyDrvRateBase: 0,

        ekt: false,

        cipherType: defs.srtpCipherType.NULL_CIPHER,
        encrypt: function (data) { return data; }, // NULL_CIPHER
        decrypt: function (data) { return data; }, // NULL_CIPHER
        PRF_n: crypto.aesCtrEncrypt,
        authHash: null,

        _init: function (ssrc, options) {
            options = options || {};

            logger.info("[SRTP] CryptoContext::init, ssrc=" + ssrc + ", masterKey: ",
                options.masterKey, ", masterSalt: ", options.masterSaltKey,
                ", keyDrvRate=" + options.keyDrvRate);
            this.ssrc = ssrc;
            this.masterKey = options.masterKey;
            this.masterSaltKey = options.masterSaltKey;
            this.sessionKeyLength = options.cipherParams.keyLength;
            this.sessionSaltKeyLength = options.cipherParams.saltLength;
            this.authKeyLength = options.authParams.keyLength;
            this.authTagLength = options.authParams.tagLength;
            this.keyDrvRate = options.keyDrvRate ? options.keyDrvRate : 0;
            this.hasMKI = options.hasMKI;
            this.ekt = options.ektParams;

            if (this.keyDrvRate > 0) {
                this.keyDrvRateBase = Math.ceil(Math.log(this.keyDrvRate) / Math.log(2));
            }

            if (options.cipherParams != undefined) {
                switch (options.cipherParams.type) {
                    case defs.srtpCipherType.NULL_CIPHER:
                        this.cipherType = defs.srtpCipherType.NULL_CIPHER;
                        break;
                    case defs.srtpCipherType.AES_CM_128:
                        this.cipherType = defs.srtpCipherType.AES_CM_128;
                        this.encrypt = crypto.aesCtrEncrypt;
                        this.decrypt = crypto.aesCtrDecrypt;
                        break;
                    default:
                        break;
                }
                switch (options.authParams.type) {
                    case defs.srtpAuthType.HAMC_SHA1:
                        this.authHash = crypto.hmacSha1;
                        break;
                    default:
                        break;
                }
            }
        },

        updateMasterKey: function (masterKey) {
            logger.info("[SRTP] updateMasterKey, new master key: ", masterKey, ", old master key: ", this.masterKey);
            this.oldMasterKey = this.masterKey;
            this.masterKey = new Uint8Array(masterKey.length);
            this.masterKey.set(masterKey, 0);
        }
    });

    /**
     * @constructor SrtpJS.srtp.RTPCryptoContext
     * @description SRTP crypto context
     * @param {Integer} ssrc the stream SSRC
     * @param {Object} options the crypto context options
     * @param {Uint8Array} options.masterKey master key
     * @param {Uint8Array} options.masterSaltKey master salt key
     * @param {Integer} options.keyDrvRate key derivation rate
     * @param {Boolean} options.hasMKI indicate if MKI is enabled
     * @param {SrtpJS.defs.srtpCryptoSuite} options.cryptoSuite the crypto suite
     * @param {Object} options.ektParams the EKT parameters if it is enabled
     * @param {SrtpJS.defs.ektCipherType} options.ektParams.cipher The EKT cipher used to encrypt the SRTP Master Key
     * @param {Uint8Array} options.ektParams.key The EKT key used to encrypt the SRTP Master Key
     * @param {Integer} options.ektParams.spi The EKT Security Parameter Index
     */
    function RTPCryptoContext(ssrc, options) {
        this._init(ssrc, options);
    }

    SrtpJS.extend(RTPCryptoContext.prototype, /** @lends RTPCryptoContext.prototype*/{
        ctx: null,

        replayItem: null,   // ReplayItem
        roc: 0,             // rollover counter, 32-bits

        firstsequence: false,
        lastSequence: 0,

        authenticate: authenticateRTPDataRFC3711, // authenticate function

        _init: function (ssrc, options) {
            options = options || {};

            var ctxOptions = {
                masterKey: options.masterKey,
                masterSaltKey: options.masterSaltKey,
                keyDrvRate: options.keyDrvRate,
                hasMKI: options.hasMKI
            }
            var hashAlgorithm = null;
            switch (options.cryptoSuite) {
                case defs.srtpCryptoSuite.NULL_CIPHER_HMAC_SHA1_80:
                    ctxOptions.cipherParams = {
                        type: defs.srtpCipherType.NULL_CIPHER,
                        keyLength: 0,
                        saltLength: 0
                    };
                    ctxOptions.authParams = {
                        type: defs.srtpAuthType.HAMC_SHA1,
                        keyLength: 20,
                        tagLength: 10
                    };
                    hashAlgorithm = crypto.hmacSha1List;
                    break;
                case defs.srtpCryptoSuite.AES_CM_128_HMAC_SHA1_80:
                    ctxOptions.cipherParams = {
                        type: defs.srtpCipherType.AES_CM_128,
                        keyLength: 16,
                        saltLength: 14
                    };
                    ctxOptions.authParams = {
                        type: defs.srtpAuthType.HAMC_SHA1,
                        keyLength: 20,
                        tagLength: 10
                    };
                    hashAlgorithm = crypto.hmacSha1List;
                    break;
                default:
                    logger.error("[SRTP] RTP::_init, invalid cryptoSuite: " + options.cryptoSuite);
                    break;
            }
            ctxOptions.ektParams = options.ektParams;
            this.ctx = new CryptoContext(ssrc, ctxOptions);
            if (hashAlgorithm) {
                this.ctx.authHash = hashAlgorithm;
            }
            this.replayItem = new ReplayItem();
        },

        generateKeys: function (sequence, roc) {
            if (this.ctx.sessionKeyLength > 0) {
                this.ctx.sessionKey = generateKey(sequence, roc, this.ctx.keyDrvRateBase, LABEL_RTP_SESSION_KEY,
                    this.ctx.sessionKeyLength, this.ctx.masterKey, this.ctx.masterSaltKey, this.ctx.PRF_n);
            }
            if (this.ctx.sessionSaltKeyLength > 0) {
                this.ctx.sessionSaltKey = generateKey(sequence, roc, this.ctx.keyDrvRateBase, LABEL_RTP_SESSION_SALT,
                    this.ctx.sessionSaltKeyLength, this.ctx.masterKey, this.ctx.masterSaltKey, this.ctx.PRF_n);
            }
            if (this.ctx.authKeyLength > 0) {
                this.ctx.authKey = generateKey(sequence, roc, this.ctx.keyDrvRateBase, LABEL_RTP_AUTH_KEY,
                    this.ctx.authKeyLength, this.ctx.masterKey, this.ctx.masterSaltKey, this.ctx.PRF_n);
            }
        },

        estimateROC: function (sequence) {
            var roc = this.roc;
            if (!this.firstsequence) { // first packet
                return roc;
            }
            seqDiff = util.calcDiffUint16(sequence, this.lastSequence);
            if (seqDiff < 0) {
                if (sequence > this.lastSequence) {
                    roc = roc - 1;
                }
            } else {
                if (sequence < this.lastSequence) {
                    roc = roc + 1;
                }
            }
            return roc;
        },

        updateSequenceAndROC: function (sequence, roc) {
            if (this.firstsequence === false) {
                this.firstsequence = sequence;
                this.lastSequence = sequence;
                this.roc = roc;
                return;
            }
            if (roc > this.roc) {
                logger.info("[SRTP] RTP::updateSequenceAndROC, update ROC, new ROC: " + roc
                    + ", old ROC: " + this.roc + ", new sequence: " + sequence
                    + ", old sequence: " + this.lastSequence);
                this.roc = roc;
                this.lastSequence = sequence;
            } else if (roc == this.roc && util.calcDiffUint16(sequence, this.lastSequence) > 0) {
                this.lastSequence = sequence;
            }
        },

        protect: function (data) {
            return null; // not support
        },

        /**
         * @method SrtpJS.srtp.RTPCryptoContext.unprotect
         * @description unprotect the RTP data
         * @param {Uint8Array} data the encrypted RTP data
         * @returns {Uint8Array} return the decrypted RTP data
         */
        unprotect: function (data) {
            var sequence, roc,
                csrcCount = 0,
                hasExtension = false,
                extLength = 0,
                hdrLength = 0,
                hdrFixedLength = 12,
                mkiLength = this.hasMKI ? 4 : 0,
                payload,
                ctx = this.ctx,
                index, iv, i, o,
                masterKeyUpdated = false
            ;

            // 1. process EKT, remove the EKT stub
            if (ctx.ekt) {
                o = srtp.ektDecode(data, ctx.ekt.key);
                switch (o.type) {
                    case defs.ektType.EKT_TYPE_SHORT:
                        data = o.data;
                        break;
                    case defs.ektType.EKT_TYPE_FULL:
                        // TODO: update master, roc, isn
                        if (!util.arrayEqual(o.masterKey, ctx.masterKey)) {
                            ctx.updateMasterKey(o.masterKey);
                            this.roc = o.roc;
                            masterKeyUpdated = true;
                        }
                        data = o.data;
                        break;
                    default:
                        return null;
                }
            }

            if (!(data instanceof Uint8Array) || data.length < hdrFixedLength + mkiLength + ctx.authTagLength) {
                logger.error("[SRTP] RTP::unprotect, invalid data length: " + data.length);
                return null; // invalid RTP data
            }

            // 2. decode sequence and estimate ROC
            sequence = (data[2] << 8) | data[3];
            roc = this.estimateROC(sequence);
            index = roc * (0xFFFFFFFF + 1) + sequence;

            // 3. replay check
            if (!this.replayItem.checkIndex(index)) {
                logger.error("[SRTP] RTP::unprotect, replayed packet, index=" + index);
                return null;
            }

            // 4. decode RTP header to get the hdrLength
            hasExtension = (data[0] & 0x10) > 0;
            csrcCount = data[0] & 0x0F;
            hdrLength = hdrFixedLength + csrcCount * 4;
            if (hasExtension) {
                hdrLength += 2; // extension type
                extLength = (data[hdrLength] << 8) | data[hdrLength + 1];
                hdrLength += 2; // extension length
                hdrLength += extLength * 4;
            }

            // 5. authenticate packet, remove the auth tag and MKI
            // TODO: considerate the key derivation rate
            if (ctx.sessionKey == null || masterKeyUpdated) {
                this.generateKeys(sequence, roc);
            }
            data = this.authenticate(ctx.authKey, ctx.authTagLength, this.ctx.hasMKI, roc, data, hdrLength, this.ctx.authHash);
            if (null == data) {
                logger.error("[SRTP] RTP::unprotect, failed to authenticate data");
                return null; // authenticate failure
            }

            // 6. decrypt payload, data
            if (hdrLength > data.length) {
                logger.error("[SRTP] RTP::unprotect, invalid data, length=" + data.length + ", hdrLength=" + hdrLength);
                return null; // invalid RTP data
            } else if (hdrLength == data.length) {
                this.updateSequenceAndROC(sequence, roc);
                return data; // empty payload ?
            }
            payload = data.subarray(hdrLength, data.length); // subarray return the view to same ArrayBuffer
            // generate IV
            iv = generateIV(ctx.ssrc, sequence, roc, ctx.sessionSaltKey);
            // decrypt payload
            payload = this.ctx.decrypt(payload, ctx.sessionKey, iv);
            if (!payload) {
                logger.error("[SRTP] RTP::unprotect, failed to decrypt data");
                return null;
            }
            data.set(payload, hdrLength);

            this.updateSequenceAndROC(sequence, roc);
            ++ctx.packetCount;

            // 7. add sequence to replay list
            this.replayItem.updateIndex(index);

            return data;
        },
    });

    /**
     * @constructor SrtpJS.srtp.RTCPCryptoContext
     * @description SRTCP crypto context
     * @param {Integer} ssrc the RTCP SSRC
     * @param {Object} options the crypto context options
     * @param {Uint8Array} options.masterKey master key
     * @param {Uint8Array} options.masterSaltKey master salt key
     * @param {Integer} options.keyDrvRate key derivation rate
     * @param {Boolean} options.hasMKI indicate if MKI is enabled
     * @param {SrtpJS.defs.srtpCryptoSuite} options.cryptoSuite the crypto suite
     * @param {Object} options.ektParams the EKT parameters if it is enabled
     * @param {SrtpJS.defs.ektCipherType} options.ektParams.cipher The EKT cipher used to encrypt the SRTP Master Key
     * @param {Uint8Array} options.ektParams.key The EKT key used to encrypt the SRTP Master Key
     * @param {Integer} options.ektParams.spi The EKT Security Parameter Index
     */
    function RTCPCryptoContext(ssrc, options) {
        this._init(ssrc, options);
    }

    SrtpJS.extend(RTCPCryptoContext.prototype, /** @lends RTCPCryptoContext.prototype*/{
        ctx: null,

        replayItem: null,   // ReplayItem
        index: 0,           // packet index

        _init: function (ssrc, options) {
            options = options || {};

            var ctxOptions = {
                masterKey: options.masterKey,
                masterSaltKey: options.masterSaltKey,
                keyDrvRate: options.keyDrvRate,
                hasMKI: options.hasMKI
            }
            switch (options.cryptoSuite) {
                case defs.srtpCryptoSuite.NULL_CIPHER_HMAC_SHA1_80:
                    ctxOptions.cipherParams = {
                        type: defs.srtpCipherType.NULL_CIPHER,
                        keyLength: 0,
                        saltLength: 0
                    };
                    ctxOptions.authParams = {
                        type: defs.srtpAuthType.HAMC_SHA1,
                        keyLength: 20,
                        tagLength: 10
                    };
                    break;
                case defs.srtpCryptoSuite.AES_CM_SW_128_HMAC_SHA1_OSW_80:
                case defs.srtpCryptoSuite.AES_CM_SW_128_HMAC_SHA1_80:
                case defs.srtpCryptoSuite.AES_CM_128_HMAC_SHA1_80:
                    ctxOptions.cipherParams = {
                        type: defs.srtpCipherType.AES_CM_128,
                        keyLength: 16,
                        saltLength: 14
                    };
                    ctxOptions.authParams = {
                        type: defs.srtpAuthType.HAMC_SHA1,
                        keyLength: 20,
                        tagLength: 10
                    };
                    break;
                default:
                    logger.error("[SRTP] RTCP::_init, invalid cryptoSuite: " + options.cryptoSuite);
                    break;
            }
            ctxOptions.ektParams = options.ektParams;
            this.ctx = new CryptoContext(ssrc, ctxOptions);

            this.replayItem = new ReplayItem();
        },

        generateKeys: function (index) {
            if (this.ctx.sessionKeyLength > 0) {
                this.ctx.sessionKey = generateKeyRTCP(index, this.ctx.keyDrvRate, LABEL_RTCP_SESSION_KEY,
                    this.ctx.sessionKeyLength, this.ctx.masterKey, this.ctx.masterSaltKey, this.ctx.PRF_n);
            }
            if (this.ctx.sessionSaltKeyLength > 0) {
                this.ctx.sessionSaltKey = generateKeyRTCP(index, this.ctx.keyDrvRate, LABEL_RTCP_SESSION_SALT,
                    this.ctx.sessionSaltKeyLength, this.ctx.masterKey, this.ctx.masterSaltKey, this.ctx.PRF_n);
            }
            if (this.ctx.authKeyLength > 0) {
                this.ctx.authKey = generateKeyRTCP(index, this.ctx.keyDrvRate, LABEL_RTCP_AUTH_KEY,
                    this.ctx.authKeyLength, this.ctx.masterKey, this.ctx.masterSaltKey, this.ctx.PRF_n);
            }
        },

        /**
         * @method SrtpJS.srtp.RTCPCryptoContext.protect
         * @description protect the RTCP data
         * @param {Uint8Array} data the RTCP data
         * @returns {Uint8Array} return the encrypted RTCP data
         */
        protect: function (data) {
            var hdrLength = 8,
                mkiLength = this.hasMKI ? 4 : 0,
                totalLength,
                payload,
                outData,
                authData,
                authTag,
                offset,
                index = this.index,
                ctx = this.ctx,
                iv
            ;
            if (!(data instanceof Uint8Array) || data.length < hdrLength) {
                return null; // invalid RTCP data
            }

            // TODO: considerate the key derivation rate and master key update
            if (ctx.sessionKey == null) {
                this.generateKeys(this.index);
            }

            offset = 0;
            totalLength = data.length + 4 + mkiLength + ctx.authTagLength;
            outData = new Uint8Array(totalLength);
            outData.set(data.subarray(0, hdrLength), 0);
            offset += hdrLength;

            // 1. encrypt the payload
            payload = data.subarray(hdrLength);
            if (payload.length > 0) {
                iv = generateIVRTCP(ctx.ssrc, this.index, ctx.sessionSaltKey);
                payload = this.ctx.encrypt(payload, ctx.sessionKey, iv);
                if (!payload) {
                    logger.error("[SRTP] RTCP::protect, failed to encrypt data");
                    return null;
                }
                outData.set(payload, hdrLength);
                offset += payload.length;
            }

            // 2. append e-flag and index
            index = this.index;
            if (ctx.cipherType != defs.srtpCipherType.NULL_CIPHER) {
                index |= 0x80000000;
            }
            outData[offset++] = (index >>> 24) & 0xFF;
            outData[offset++] = (index >>> 16) & 0xFF;
            outData[offset++] = (index >>> 8) & 0xFF;
            outData[offset++] = index & 0xFF;

            // 3. do authenticate
            authData = outData.subarray(0, offset);
            authTag = this.ctx.authHash(authData, ctx.authKey);
            authTag = authTag.subarray(0, ctx.authTagLength);

            // 4. append MKI if any
            if (ctx.hasMKI) {
                outData[offset++] = 0;
                outData[offset++] = 0;
                outData[offset++] = 0;
                outData[offset++] = 0;
            }

            // 5. append authenticate tag
            outData.set(authTag, offset);

            // 6. append EKT part
            if (ctx.ekt) {
                var o = {};
                if (0 == this.index) {
                    o.type = defs.ektType.EKT_TYPE_FULL;
                    o.masterKey = ctx.masterKey;
                    o.ssrc = ctx.ssrc;
                    o.roc = 0; // receive only
                    o.isn = 0; // receive only
                    o.spi = ctx.ekt.spi;
                    o.data = outData;
                } else {
                    o.type = defs.ektType.EKT_TYPE_SHORT;
                    o.data = outData;
                }
                outData = srtp.ektEncode(o, ctx.ekt.key);
                if (null == outData) {
                    return null;
                }
            }

            ++this.index;
            this.index &= 0x7FFFFFFF;
            ++ctx.packetCount;
            return outData;
        },

        /**
         * @method SrtpJS.srtp.RTCPCryptoContext.unprotect
         * @description unprotect the RTCP data
         * @param {Uint8Array} data the encrypted RTCP data
         * @returns {Uint8Array} return the decrypted RTCP data
         */
        unprotect: function (data) {
            var mkiLength = this.hasMKI ? 4 : 0,
                hdrLength = 8,
                mki, index, eFlag,
                orgAuthTag,
                newAuthTag,
                masterKeyUpdated = false,
                ctx = this.ctx
            ;
            // 1. process EKT, remove the EKT stub
            if (ctx.ekt) {
                o = srtp.ektDecode(data, ctx.ekt.key);
                switch (o.type) {
                    case defs.ektType.EKT_TYPE_SHORT:
                        data = o.data;
                        break;
                    case defs.ektType.EKT_TYPE_FULL:
                        // TODO: update master, roc, isn
                        if (!util.arrayEqual(o.masterKey, ctx.masterKey)) {
                            ctx.updateMasterKey(o.masterKey);
                            masterKeyUpdated = true;
                        }
                        data = o.data;
                        break;
                    default:
                        return null;
                }
            }

            if (!(data instanceof Uint8Array) || data.length < hdrLength + mkiLength + 4 + ctx.authTagLength) { // RTCP header, MKI, index, auth tag
                logger.error("[SRTP] RTCP::unprotect, invalid data length: " + data.length);
                return null; // invalid RTP data
            }

            // decode auth tag, MKI, index, e-falg
            orgAuthTag = data.subarray(data.length - ctx.authTagLength);
            if (ctx.hasMKI) {
                mki = data[data.length - ctx.authTagLength - 1] |
                    (data[data.length - ctx.authTagLength - 2] << 8) |
                    (data[data.length - ctx.authTagLength - 3] << 16) |
                    (data[data.length - ctx.authTagLength - 4] << 24);
            }
            index = data[data.length - ctx.authTagLength - mkiLength - 1] |
                    (data[data.length - ctx.authTagLength - mkiLength - 2] << 8) |
                    (data[data.length - ctx.authTagLength - mkiLength - 3] << 16) |
                    (data[data.length - ctx.authTagLength - mkiLength - 4] << 24);
            eFlag = index >>> 31;
            index = index & 0x7FFFFFFF;

            // 3. replay check
            if (!this.replayItem.checkIndex(index)) {
                logger.error("[SRTP] RTCP::unprotect, replayed packet, index=" + index);
                return null;
            }

            // 4. authenticate packet, remove the auth tag and MKI
            // TODO: considerate the key derivation rate
            if (ctx.sessionKey == null || masterKeyUpdated) {
                this.generateKeys(index);
            }

            // now data include header, payload, e-flag and index
            data = data.subarray(0, data.length - ctx.authTagLength - mkiLength);
            newAuthTag = this.ctx.authHash(data, ctx.authKey);
            newAuthTag = newAuthTag.subarray(0, ctx.authTagLength);
            if (!util.arrayEqual(newAuthTag, orgAuthTag)) {
                logger.error("[SRTP] RTCP::unprotect, failed to authenticate data");
                return null;// authenticate failure
            }
            data = data.subarray(0, data.length - 4); // remove the e-flag and index

            // 5. decrypt payload
            if (eFlag != 0) {
                payload = data.subarray(hdrLength); // subarray return the view to same ArrayBuffer
                // generate IV
                iv = generateIVRTCP(ctx.ssrc, index, ctx.sessionSaltKey);
                // decrypt payload
                payload = this.ctx.decrypt(payload, ctx.sessionKey, iv);
                if (!payload) {
                    logger.error("[SRTP] RTCP::unprotect, failed to decrypt data");
                    return null;
                }
                data.set(payload, hdrLength);
            }

            ++ctx.packetCount;

            // 6. add index to replay list
            this.replayItem.updateIndex(index)

            return data;
        }
    });

    /**
     * @function generateKey
     * @description generate the session keys
     * @param {Integer} sequence the packet sequence number
     * @param {Integer} roc the rollover counter
     * @param {Integer} keyDrvRateBase key derivation rate base (log(keyDrvRate, 2))
     * @param {Integer} keyLable key label
     * @param {Integer} keyLength the length of key to be generated
     * @param {Uint8Array} masterKey the master key
     * @param {Uint8Array} masterSalt the master salt key
     * @returns {Uint8Array} return the generated key
     */
    function generateKey(sequence, roc, keyDrvRateBase, keyLable, keyLength, masterKey, masterSalt, PRF_n) {
        var iv, n16, n32, i, sz, key;
        iv = new Uint8Array(crypto.AES_BLOCK_SIZE);
        // RFC 3711, 4.1.1 in AES-CM, IV is formed by "reserving" 16 zeros in the least significant bits for the purpose of the counter
        if (keyDrvRateBase != 0) {
            if (keyDrvRateBase >= 16) {
                n16 = (roc >>> (keyDrvRateBase - 16)) & 0xFF;
            } else {
                n16 = (sequence >>> keyDrvRateBase) | ((roc & ((1 << keyDrvRateBase) - 1)) << (16 - keyDrvRateBase));
            }
            n32 = roc >>> keyDrvRateBase;
            iv[iv.length - 3] = (n16 & 0xFF);
            iv[iv.length - 4] = ((n16 >>> 8) & 0xFF);
            iv[iv.length - 5] = (n32 & 0xFF);
            iv[iv.length - 6] = ((n32 >>> 8) & 0xFF);
            iv[iv.length - 7] = ((n32 >>> 16) & 0xFF);
            iv[iv.length - 8] = ((n32 >>> 24) & 0xFF);
        }
        iv[iv.length - 9] = keyLable;
        if (masterSalt && masterSalt instanceof Uint8Array) {
            // the least two bytes of IV is for counter
            sz = masterSalt.length > (iv.length - 2) ? (iv.length - 2) : masterSalt.length;
            for (i = 0; i < sz; ++i) {
                iv[iv.length - 3 - i] = iv[iv.length - 3 - i] ^ masterSalt[masterSalt.length - 1 - i];
            }
        }
        // generate key, AES-CM PRF_n(masterKey, iv)
        key = new Uint8Array(keyLength);
        key = PRF_n(key, masterKey, iv);
        return key;
    }

    /**
     * @function generateIV
     * @description generate the AES initial vector
     * @param {Integer} ssrc RTP SSRC
     * @param {Integer} sequence the packet sequence number
     * @param {Integer} roc the rollover counter
     * @param {Uint8Array} salt the session salt key
     * @returns {Uint8Array} return the AES initial vector
     */
    function generateIV(ssrc, sequence, roc, salt) {
        var iv, i, sz, idx;
        iv = new Uint8Array(crypto.AES_BLOCK_SIZE);
        idx = crypto.AES_BLOCK_SIZE;
        iv[--idx] = 0;
        iv[--idx] = 0;
        iv[--idx] = sequence & 0xFF;
        iv[--idx] = (sequence >>> 8) & 0xFF;
        iv[--idx] = roc & 0xFF;
        iv[--idx] = (roc >>> 8) & 0xFF;
        iv[--idx] = (roc >>> 16) & 0xFF;
        iv[--idx] = (roc >>> 24) & 0xFF;
        iv[--idx] = ssrc & 0xFF;
        iv[--idx] = (ssrc >>> 8) & 0xFF;
        iv[--idx] = (ssrc >>> 16) & 0xFF;
        iv[--idx] = (ssrc >>> 24) & 0xFF;

        if (salt && salt instanceof Uint8Array) {
            sz = salt.length > (iv.length - 2) ? (iv.length - 2) : salt.length;
            for (i = 0; i < sz; ++i) {
                iv[iv.length - 3 - i] = iv[iv.length - 3 - i] ^ salt[salt.length - 1 - i];
            }
        }
        return iv;
    }

    /**
     * @function generateKeyRTCP
     * @description generate the RTCP session keys
     * @param {Integer} index the index of RTCP packet
     * @param {Integer} keyDrvRate key derivation rate
     * @param {Integer} keyLable key label
     * @param {Integer} keyLength the length of key to be generated
     * @param {Uint8Array} masterKey the master key
     * @param {Uint8Array} masterSalt the master salt key
     * @returns {Uint8Array} return the generated key
     */
    function generateKeyRTCP(index, keyDrvRate, keyLable, keyLength, masterKey, masterSalt, PRF_n) {
        var iv, r, i, sz, key;
        iv = new Uint8Array(crypto.AES_BLOCK_SIZE);
        if (keyDrvRate != 0) {
            r = Math.floor(index / keyDrvRate);
            iv[iv.length - 3] = (r & 0xFF);
            iv[iv.length - 4] = ((r >>> 8) & 0xFF);
            iv[iv.length - 5] = ((r >>> 16) & 0xFF);
            iv[iv.length - 6] = ((r >>> 24) & 0xFF);
        }
        // FIXME: should it be 7 or 9? the index of RTCP is 32-bits
        //iv[iv.length - 7] = keyLable;
        iv[iv.length - 9] = keyLable; // use 9 in accord with libsrtp
        if (masterSalt && masterSalt instanceof Uint8Array) {
            sz = masterSalt.length > (iv.length - 2) ? (iv.length - 2) : masterSalt.length;
            for (i = 0; i < sz; ++i) {
                iv[iv.length - 3 - i] = iv[iv.length - 3 - i] ^ masterSalt[masterSalt.length - 1 - i];
            }
        }
        // generate key, AES-CM PRF_n(masterKey, iv)
        key = new Uint8Array(keyLength);
        key = PRF_n(key, masterKey, iv);
        return key;
    }

    /**
     * @function generateIVRTCP
     * @description generate the AES initial vector
     * @param {Integer} ssrc RTCP SSRC
     * @param {Integer} index the index of RTCP packet
     * @param {Uint8Array} salt the session salt key
     * @returns {Uint8Array} return the AES initial vector
     */
    function generateIVRTCP(ssrc, index, salt) {
        var iv, i, sz, idx;
        iv = new Uint8Array(crypto.AES_BLOCK_SIZE);
        idx = crypto.AES_BLOCK_SIZE;
        iv[--idx] = 0;
        iv[--idx] = 0;
        iv[--idx] = index & 0xFF;
        iv[--idx] = (index >>> 8) & 0xFF;
        iv[--idx] = (index >>> 16) & 0xFF;
        iv[--idx] = (index >>> 24) & 0xFF;
        iv[--idx] = 0;
        iv[--idx] = 0;
        iv[--idx] = ssrc & 0xFF;
        iv[--idx] = (ssrc >>> 8) & 0xFF;
        iv[--idx] = (ssrc >>> 16) & 0xFF;
        iv[--idx] = (ssrc >>> 24) & 0xFF;

        if (salt && salt instanceof Uint8Array) {
            sz = salt.length > (iv.length - 2) ? (iv.length - 2) : salt.length;
            for (i = 0; i < sz; ++i) {
                iv[iv.length - 3 - i] = iv[iv.length - 3 - i] ^ salt[salt.length - 1 - i];
            }
        }
        return iv;
    }

    /**
     * @function authenticateRTPDataRFC3711
     * @description authenticate the RTP data according to RFC 3711
     * @param {Uint8Array} authKey the authenticate key
     * @param {Integer} authTaglength the length of authenticate length
     * @param {Boolean} hasMKI indicate if the MKI is exist
     * @param {Integer} roc ROC
     * @param {Uint8Array} data the data to be authenticated
     * @param {Integer} hdrLength the header length of RTP (include extension length)
     * @param {Function} authHash the hash function, can be hmacSha1List
     * @returns {Uint8Array} return the RTP data without autenticate tag
     */
    function authenticateRTPDataRFC3711(authKey, authTagLength, hasMKI, roc, data, hdrLength, authHash) {
        var orgAuthTag,
            newAuthTag,
            mkiLength = hasMKI ? 4 : 0,
            mki, rocd
        ;
        orgAuthTag = data.subarray(data.length - authTagLength);
        if (hasMKI) {
            mki = data[data.length - ctx.authTagLength - 1] |
                (data[data.length - ctx.authTagLength - 2] << 8) |
                (data[data.length - ctx.authTagLength - 3] << 16) |
                (data[data.length - ctx.authTagLength - 4] << 24);
        }
        // remove MKI and authenticate tag, now data include header, payload
        data = data.subarray(0, data.length - authTagLength - mkiLength);
        rocd = new Uint8Array(4);
        rocd[0] = (roc >>> 24) & 0xFF;
        rocd[0] = (roc >>> 16) & 0xFF;
        rocd[0] = (roc >>> 8) & 0xFF;
        rocd[0] = roc & 0xFF;
        var authList = [
            data,
            rocd
        ];
        newAuthTag = authHash(authList, authKey);
        newAuthTag = newAuthTag.subarray(0, authTagLength);
        if (!util.arrayEqual(newAuthTag, orgAuthTag)) {
            return null; // authenticate failure
        }
        return data;
    }

    function ReplayItem() {
    }

    SrtpJS.extend(ReplayItem.prototype, {
        replayList: null,
        lastIndex: 0,

        checkIndex: function (index) {
            if (null == this.replayList) {
                return true;
            }
            var diff = index - this.lastIndex;
            if (diff > 0) {
                if (diff > REPLAY_ITEM_SIZE) {
                    return false;
                }
                return true;
            } else if (diff < 0) {
                diff = -diff;
                if (diff > REPLAY_ITEM_SIZE || this.replayList[this.replayList.length - diff]) {
                    return false;
                }
                return true;
            }
            return false;
        },

        updateIndex: function (index) {
            if (null == this.replayList) {
                this.replayList = new Array(REPLAY_ITEM_SIZE);
                this.lastIndex = index;
                return true;
            }
            var diff = index - this.lastIndex;
            if (diff > 0) {
                if (diff > REPLAY_ITEM_SIZE) {
                    return false;
                }
                this.replayList.splice(0, diff);
                this.replayList.push(1);
                for (var i = 0; i < diff - 1; ++i) {
                    this.replayList.push(0);
                }
                this.lastIndex = index;
                return true;
            } else if (diff < 0) {
                diff = -diff;
                if (diff > REPLAY_ITEM_SIZE || this.replayList[this.replayList.length - diff]) {
                    return false;
                }
                this.replayList[this.replayList.length - diff] = 1;
                return true;
            }
            return false;
        }
    });

    /**
     * @description namespace of SrtpJS.srtp
     * @namespace SrtpJS.srtp
     */

    srtp.RTPCryptoContext = RTPCryptoContext;
    srtp.RTCPCryptoContext = RTCPCryptoContext;
    srtp.ReplayItem = ReplayItem;  // for unit test
    srtp.generateKey = generateKey;  // for unit test
    srtp.generateIV = generateIV;  // for unit test
    srtp.generateKeyRTCP = generateKeyRTCP;  // for unit test
    srtp.generateIVRTCP = generateIVRTCP;  // for unit test
    exports.srtp = srtp;
    return srtp;
})(SrtpJS);
