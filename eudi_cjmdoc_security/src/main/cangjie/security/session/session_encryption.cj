/*
 * session_encryption.cj — ISO 18013-5 §9.1.1 session encryption for mDoc.
 *
 * Implements:
 *   - SessionRole enum (mdoc holder role)
 *   - SessionTranscript CBOR struct (§9.1.1.2)
 *   - SessionEstablishment CBOR struct (reader → device, §9.1.1.3)
 *   - SessionData CBOR struct (encrypted message wrapper, §9.1.1.4)
 *   - SessionEncryption class (ECDH + HKDF + AES-GCM, §9.1.1.5)
 *
 * Crypto delegation:
 *   - ECDH via EcdhP256.agree() (eudi_lib_core_crypto, HUKS alias based) or a
 *     SessionKeyAgreement provider (SecureArea-resident ephemeral key)
 *   - HKDF via Hkdf.derive() (eudi_lib_core_crypto, RFC 5869 HMAC-SHA256)
 *   - AES-256-GCM via AesGcm.seal()/open() (eudi_lib_core_crypto)
 *
 * CBOR encoding: all CBOR structures use the ohos_app_cangjie_eudi_cjcbor library
 * (CborValue / CborTag / decodeCbor) — canonical RFC 8949 bytewise map order.
 *
 * iOS sources mirrored:
 *   Sources/MdocSecurity18013/SessionEncryption/SessionEncryption.swift
 *   Sources/MdocSecurity18013/SessionEncryption/EckaDHAgreement.swift
 *   Sources/MdocSecurity18013/SessionEncryption/SessionRole.swift
 *   Sources/MdocSecurity18013/SessionEncryption/SessionTranscript.swift
 *   Sources/MdocSecurity18013/SessionEncryption/SessionEstablishment.swift
 *   Sources/MdocSecurity18013/SessionEncryption/SessionData.swift
 */
package ohos_app_cangjie_eudi_cjmdoc_security.security.session

import std.collection.ArrayList
import eudi_lib_core_crypto.EcdhP256
import eudi_lib_core_crypto.AesGcm
import eudi_lib_core_crypto.Hkdf
import eudi_lib_core_crypto.CoreCryptoException
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.engagement.CoseKey
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.engagement.CoseKeyPrivate
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.engagement.CoseKeyExchange
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.core.MdocValidationError
import ohos_app_cangjie_eudi_cjcbor.cbor.CborValue
import ohos_app_cangjie_eudi_cjcbor.cbor.CborTag
import ohos_app_cangjie_eudi_cjcbor.cbor.decodeCbor

/* ==================================================================== */
/* SessionRole — role of this session endpoint                           */
/* ==================================================================== */

/**
 * The role of a session participant in the ISO 18013-5 mDoc protocol.
 * Only `Mdoc` is defined here (the holder/device role).
 *
 * iOS: SessionRole.swift
 */
public enum SessionRole {
    /** mDoc (holder/device) role. Encrypts with SKDevice, decrypts with SKReader. */
    | Mdoc
}

/* ==================================================================== */
/* Non-CBOR helper — nonce counter big-endian                           */
/* ==================================================================== */

/**
 * Encode a UInt32 as 4-byte big-endian.
 */
func uint32ToBigEndian(value: UInt32): Array<UInt8> {
    let out = Array<UInt8>(4, repeat: 0)
    out[0] = UInt8((value >> UInt32(24)) & UInt32(0xFF))
    out[1] = UInt8((value >> UInt32(16)) & UInt32(0xFF))
    out[2] = UInt8((value >> UInt32(8)) & UInt32(0xFF))
    out[3] = UInt8(value & UInt32(0xFF))
    return out
}

/**
 * Convert a String to UTF-8 bytes.
 *
 * S-018 compliant: uses toRuneArray() + Rune.utf8Size() + Rune.intoUtf8Array()
 * instead of for-in + Rune.toString() which is broken on device (S-018).
 * Rune.intoUtf8Array(c, arr, index) writes UTF-8 bytes of c into arr starting
 * at index and returns the number of bytes written.
 */
func stringToUtf8Bytes(s: String): Array<UInt8> {
    let runes = s.toRuneArray()
    // First pass: compute total UTF-8 byte count
    var totalSize: Int64 = 0
    var i: Int64 = 0
    while (i < runes.size) {
        totalSize += Rune.utf8Size(runes[i])
        i += 1
    }
    // Second pass: fill buffer
    let buf = Array<UInt8>(totalSize, repeat: 0)
    var offset: Int64 = 0
    var j: Int64 = 0
    while (j < runes.size) {
        let written = Rune.intoUtf8Array(runes[j], buf, offset)
        offset += written
        j += 1
    }
    return buf
}

/* ==================================================================== */
/* HUKS ECC P-256 DER public key construction helper                    */
/* ==================================================================== */

/**
 * Build a DER-encoded SubjectPublicKeyInfo for a P-256 uncompressed public key
 * from raw X and Y coordinate byte arrays (each 32 bytes).
 *
 * DER layout (91 bytes total):
 *   30 59                          SEQUENCE
 *     30 13                        SEQUENCE (algorithm)
 *       06 07 2a 86 48 ce 3d 02 01  OID id-ecPublicKey
 *       06 08 2a 86 48 ce 3d 03 01 07  OID prime256v1
 *     03 42 00                     BIT STRING (uncompressed)
 *       04 <X:32> <Y:32>
 *
 * This format is required by EcdhP256.agree() which expects the HUKS-exported
 * public key material (X.509/DER format per HUKS documentation).
 */
public func buildP256DerPublicKey(x: Array<UInt8>, y: Array<UInt8>): Array<UInt8> {
    if (x.size != 32 || y.size != 32) {
        throw CoreCryptoException("P-256 key coordinates must each be 32 bytes")
    }
    let der = Array<UInt8>(91, repeat: 0)
    // SEQUENCE header for outer (length = 89 = 0x59)
    der[0] = UInt8(0x30)
    der[1] = UInt8(0x59)
    // SEQUENCE header for AlgorithmIdentifier (length = 19 = 0x13)
    der[2] = UInt8(0x30)
    der[3] = UInt8(0x13)
    // OID id-ecPublicKey: 1.2.840.10045.2.1 (7 bytes content)
    der[4] = UInt8(0x06)
    der[5] = UInt8(0x07)
    der[6] = UInt8(0x2A)
    der[7] = UInt8(0x86)
    der[8] = UInt8(0x48)
    der[9] = UInt8(0xCE)
    der[10] = UInt8(0x3D)
    der[11] = UInt8(0x02)
    der[12] = UInt8(0x01)
    // OID prime256v1: 1.2.840.10045.3.1.7 (8 bytes content)
    der[13] = UInt8(0x06)
    der[14] = UInt8(0x08)
    der[15] = UInt8(0x2A)
    der[16] = UInt8(0x86)
    der[17] = UInt8(0x48)
    der[18] = UInt8(0xCE)
    der[19] = UInt8(0x3D)
    der[20] = UInt8(0x03)
    der[21] = UInt8(0x01)
    der[22] = UInt8(0x07)
    // BIT STRING: tag=03, length=66=0x42, unused-bits=00, then 04 || X || Y
    der[23] = UInt8(0x03)
    der[24] = UInt8(0x42)
    der[25] = UInt8(0x00)  // unused bits = 0
    der[26] = UInt8(0x04)  // uncompressed point prefix
    var i: Int64 = 0
    while (i < 32) {
        der[27 + i] = x[i]
        i += 1
    }
    var j: Int64 = 0
    while (j < 32) {
        der[59 + j] = y[j]
        j += 1
    }
    return der
}

/**
 * Uncompressed x963 point (0x04 || X || Y) from raw P-256 coordinates.
 * This is the peer-key form the SecureArea.keyAgreement contract expects.
 */
public func buildP256X963PublicKey(x: Array<UInt8>, y: Array<UInt8>): Array<UInt8> {
    if (x.size != 32 || y.size != 32) {
        throw CoreCryptoException("P-256 key coordinates must each be 32 bytes")
    }
    let out = Array<UInt8>(65, repeat: 0)
    out[0] = UInt8(0x04)
    var i: Int64 = 0
    while (i < 32) {
        out[1 + i] = x[i]
        out[33 + i] = y[i]
        i += 1
    }
    return out
}

/* ==================================================================== */
/* SessionKeyAgreement — ECKA-DH provider seam                           */
/* ==================================================================== */

/**
 * ECKA-DH provider for a session whose private key does not live behind a
 * bare HUKS alias — e.g. an ephemeral EDeviceKey created through a
 * SecureArea (HUKS or software). SessionEncryption calls it once per session
 * and caches the shared secret.
 *
 * iOS: CoseKeyPrivate.secureArea.keyAgreement(...) inside makeEckaDHAgreement.
 */
public interface SessionKeyAgreement {
    /**
     * @param peerPublicKeyX963  The reader's ephemeral public key as an
     *                           uncompressed x963 point (0x04 || X || Y).
     * @return raw ECDH shared secret bytes.
     */
    func agree(peerPublicKeyX963: Array<UInt8>): Array<UInt8>
}

/* ==================================================================== */
/* SessionTranscript — §9.1.1.2                                          */
/* ==================================================================== */

/**
 * SessionTranscript = [DeviceEngagementBytes, EReaderKeyBytes, Handover]
 *
 * The transcript bytes are used as the HKDF salt and as part of the
 * DeviceAuthentication structure.
 *
 * Fields:
 *   devEngRawData   — raw CBOR bytes of DeviceEngagement (NOT tag-24 here)
 *   eReaderRawData  — raw CBOR bytes of the eReaderKey map (NOT tag-24 here)
 *   handOverBytes   — raw CBOR bytes of the handover value (protocol-specific)
 *
 * iOS: SessionTranscript.swift
 */
public class SessionTranscript {
    /** Raw CBOR bytes of DeviceEngagement (NOT tag-24 wrapped). */
    public let devEngRawData: ?Array<UInt8>
    /** Raw CBOR bytes of the eReaderKey CBOR map (NOT tag-24 wrapped). */
    public let eReaderRawData: ?Array<UInt8>
    /** Raw CBOR bytes of the handover value (already encoded). */
    public let handOverBytes: Array<UInt8>

    public init(
        devEngRawData: ?Array<UInt8>,
        eReaderRawData: ?Array<UInt8>,
        handOverBytes: Array<UInt8>
    ) {
        this.devEngRawData = devEngRawData
        this.eReaderRawData = eReaderRawData
        this.handOverBytes = handOverBytes
    }

    /**
     * Encode as a CBOR array [tag24(devEng)|null, tag24(eReader)|null, handover].
     *
     * Following the iOS SessionTranscript.toCBOR pattern:
     *   devEngRawData?.taggedEncoded  → CBOR.tagged(24, .byteString(rawBytes))
     *   eReaderRawData?.taggedEncoded → CBOR.tagged(24, .byteString(rawBytes))
     *   handOver                      → as-is (pre-encoded bytes decoded back to CborValue)
     *
     * Returns the raw CBOR bytes of the array.
     * Uses ohos_app_cangjie_eudi_cjcbor library for canonical encoding.
     */
    public func toCborBytes(): Array<UInt8> {
        let items = ArrayList<CborValue>()
        // Element 0: devEng — tag24(devEngRawData) or null
        match (devEngRawData) {
            case Some(b) =>
                items.add(CborValue.TaggedVal(CborTag.ENCODED_CBOR, CborValue.ByteStringVal(b)))
            case None =>
                items.add(CborValue.NullVal)
        }
        // Element 1: eReaderKey — tag24(eReaderRawData) or null
        match (eReaderRawData) {
            case Some(b) =>
                items.add(CborValue.TaggedVal(CborTag.ENCODED_CBOR, CborValue.ByteStringVal(b)))
            case None =>
                items.add(CborValue.NullVal)
        }
        // Element 2: handOver (pre-encoded bytes — decode then re-encode to get CborValue)
        items.add(decodeCbor(handOverBytes))
        return CborValue.ArrayVal(items).encode()
    }

    /**
     * Canonical SessionTranscriptBytes = tag24(toCborBytes()).
     * Used as the HKDF salt per ISO 18013-5 §9.1.1.
     *
     * iOS: sessionTranscriptBytes = sessionTranscript.taggedEncoded.encode()
     */
    public func toTaggedBytes(): Array<UInt8> {
        return CborValue.TaggedVal(CborTag.ENCODED_CBOR, CborValue.ByteStringVal(this.toCborBytes())).encode()
    }
}

/* ==================================================================== */
/* SessionEstablishment — §9.1.1.3                                       */
/* ==================================================================== */

/**
 * SessionEstablishment is sent from the mdoc reader to the mdoc device.
 * Contains the reader's ephemeral public key (eReaderKey) and the
 * encrypted mdoc request (data field).
 *
 * CBOR map: {"eReaderKey": tag24(CoseKeyMap), "data": bstr}
 *
 * iOS: SessionEstablishment.swift
 */
public class SessionEstablishment {
    /** Raw CBOR bytes of the eReaderKey CBOR map (the payload inside tag-24). */
    public let eReaderKeyRawData: ?Array<UInt8>
    /** Encrypted mdoc request bytes. */
    public let data: Array<UInt8>

    public init(eReaderKeyRawData: ?Array<UInt8>, data: Array<UInt8>) {
        this.eReaderKeyRawData = eReaderKeyRawData
        this.data = data
    }

    /**
     * Encode as CBOR map bytes using the cbor library.
     * {"data": bstr, "eReaderKey": tag24(eReaderKeyRawData)}
     *
     * Map key order is handled canonically by CborValue.MapVal (RFC 8949 §4.2.1
     * bytewise-lexicographic, matching SwiftCBOR). "data" < "eReaderKey" in
     * bytewise ordering (0x64 < 0x65), so data comes first.
     */
    public func toCborBytes(): Array<UInt8> {
        let pairs = ArrayList<(CborValue, CborValue)>()
        // "data" entry
        pairs.add((CborValue.TextStringVal("data"), CborValue.ByteStringVal(data)))
        // "eReaderKey" entry (only if present)
        match (eReaderKeyRawData) {
            case Some(raw) =>
                pairs.add((CborValue.TextStringVal("eReaderKey"), CborValue.TaggedVal(CborTag.ENCODED_CBOR, CborValue.ByteStringVal(raw))))
            case None => ()
        }
        return CborValue.MapVal(pairs).encode()
    }

    /**
     * Decode from raw CBOR bytes using the cbor library.
     */
    public static func fromCborBytes(rawBytes: Array<UInt8>): SessionEstablishment {
        if (rawBytes.size == 0) {
            throw MdocValidationError.invalidCbor("SessionEstablishment: empty bytes")
        }
        let cbor = decodeCbor(rawBytes)
        match (cbor) {
            case CborValue.MapVal(_) =>
                // "data" field — required byte string
                let dataOpt = cbor.field(CborValue.TextStringVal("data"))
                let parsedData: Array<UInt8> = match (dataOpt) {
                    case Some(CborValue.ByteStringVal(b)) => b
                    case Some(_) => throw MdocValidationError.invalidCbor("SessionEstablishment: 'data' must be byte string")
                    case None => throw MdocValidationError.missingField("SessionEstablishment", "data")
                }
                // "eReaderKey" field — optional tag24(bstr).
                // Tag-24 (ENCODED_CBOR) wraps a ByteString whose content is the raw
                // bytes of the embedded CBOR value.  We want those raw bytes directly —
                // do NOT call decodeEmbedded (that would parse the bytes as CBOR and
                // re-encode them, potentially losing canonical ordering from the peer).
                let eReaderKeyOpt = cbor.field(CborValue.TextStringVal("eReaderKey"))
                let parsedEReaderKey: ?Array<UInt8> = match (eReaderKeyOpt) {
                    case Some(CborValue.TaggedVal(_, CborValue.ByteStringVal(b))) => Some(b)
                    case Some(_) => throw MdocValidationError.invalidCbor("SessionEstablishment: 'eReaderKey' must be tag-24(bstr)")
                    case None => None
                }
                return SessionEstablishment(parsedEReaderKey, parsedData)
            case _ =>
                throw MdocValidationError.invalidCbor("SessionEstablishment: expected CBOR map")
        }
    }
}

/* ==================================================================== */
/* SessionData — §9.1.1.4                                                */
/* ==================================================================== */

/**
 * SessionData transfers encrypted mDoc response data between device and reader.
 *
 * CBOR map: {"status": uint (optional), "data": bstr (optional)}
 *
 * iOS: SessionData.swift
 */
public class SessionData {
    public let data: ?Array<UInt8>
    public let status: ?UInt64

    public init(data: ?Array<UInt8>, status: ?UInt64) {
        this.data = data
        this.status = status
    }

    /** Convenience: create with cipher data only (no status). */
    public static func withData(cipherData: Array<UInt8>): SessionData {
        return SessionData(Some(cipherData), None)
    }

    /** Convenience: create with status only (session termination). */
    public static func withStatus(code: UInt64): SessionData {
        return SessionData(None, Some(code))
    }

    /**
     * Encode as CBOR map bytes using the cbor library.
     * Field order: status (if present), then data (if present).
     * iOS: toCBOR encodes in insertion order via OrderedDictionary.
     *
     * Note: CborValue.MapVal encodes with RFC 8949 §4.2.1 bytewise-lexicographic
     * key order. "data"(0x64) < "status"(0x73) so data sorts before status.
     * To preserve iOS insertion order (status first, then data) we insert in that
     * order and rely on the fact that the cbor library sorts the keys canonically
     * on encode — both orderings are valid CBOR; the library guarantees canonical.
     */
    public func toCborBytes(): Array<UInt8> {
        let pairs = ArrayList<(CborValue, CborValue)>()
        match (status) {
            case Some(st) =>
                pairs.add((CborValue.TextStringVal("status"), CborValue.UInt64Val(st)))
            case None => ()
        }
        match (data) {
            case Some(d) =>
                pairs.add((CborValue.TextStringVal("data"), CborValue.ByteStringVal(d)))
            case None => ()
        }
        return CborValue.MapVal(pairs).encode()
    }

    /**
     * Decode from raw CBOR bytes using the cbor library.
     */
    public static func fromCborBytes(rawBytes: Array<UInt8>): SessionData {
        if (rawBytes.size == 0) {
            throw MdocValidationError.invalidCbor("SessionData: empty bytes")
        }
        let cbor = decodeCbor(rawBytes)
        match (cbor) {
            case CborValue.MapVal(_) =>
                // "data" field — optional byte string
                let dataOpt = cbor.field(CborValue.TextStringVal("data"))
                let parsedData: ?Array<UInt8> = match (dataOpt) {
                    case Some(CborValue.ByteStringVal(b)) => Some(b)
                    case Some(_) => throw MdocValidationError.invalidCbor("SessionData: 'data' must be byte string")
                    case None => None
                }
                // "status" field — optional uint
                let statusOpt = cbor.field(CborValue.TextStringVal("status"))
                let parsedStatus: ?UInt64 = match (statusOpt) {
                    case Some(CborValue.UInt64Val(v)) => Some(v)
                    case Some(_) => throw MdocValidationError.invalidCbor("SessionData: 'status' must be uint")
                    case None => None
                }
                return SessionData(parsedData, parsedStatus)
            case _ =>
                throw MdocValidationError.invalidCbor("SessionData: expected CBOR map")
        }
    }
}

/* ==================================================================== */
/* SessionEncryption — §9.1.1.5                                          */
/* ==================================================================== */

/**
 * Session encryption for the ISO 18013-5 mDoc protocol.
 *
 * Implements ECKA-DH (BSI TR-03111) key agreement combined with HKDF-SHA256
 * key derivation and AES-256-GCM authenticated encryption.
 *
 * Nonce construction (§9.1.1.5):
 *   IV = identifier(8B) || counter(4B big-endian)
 *   - mdoc encrypts:  identifier = [0,0,0,0,0,0,0,1]  (IDENTIFIER1)
 *   - mdoc decrypts:  identifier = [0,0,0,0,0,0,0,0]  (IDENTIFIER0)
 *
 * Session key derivation:
 *   SKDevice = HKDF(salt=SessionTranscriptBytes, IKM=sharedSecret, info="SKDevice", 32)
 *   SKReader = HKDF(salt=SessionTranscriptBytes, IKM=sharedSecret, info="SKReader", 32)
 *
 * The mdoc device uses SKDevice for encryption, SKReader for decryption.
 *
 * Message counters (§9.1.1.5): each direction keeps its own counter, starting
 * at 1 and incremented after every message encrypted with that key. The mdoc
 * therefore counts the messages it encrypts (deviceCounter, SKDevice) and the
 * reader messages it decrypts (readerCounter, SKReader) independently —
 * a deliberate deviation from the single iOS counter (which only works there
 * because iOS copies the struct before each encrypt).
 *
 * iOS: SessionEncryption.swift, EckaDHAgreement.swift
 */
public class SessionEncryption {
    /** Role for this session endpoint. */
    public let sessionRole: SessionRole
    /** Counter for the messages this endpoint encrypts (SKDevice); starts at 1. */
    public var deviceCounter: UInt32
    /** Counter for the messages this endpoint decrypts (SKReader); starts at 1. */
    public var readerCounter: UInt32
    /**
     * Optional ECKA-DH provider. When set, the shared secret comes from it
     * (SecureArea-resident device key); when None the private key id is
     * treated as a HUKS alias and EcdhP256.agree is used directly.
     */
    public var keyAgreement: ?SessionKeyAgreement
    /** Shared secret cached after the first agreement (same session keys). */
    private var cachedSharedSecret: ?Array<UInt8>
    /** Key exchange pair (peer public key + own private key). */
    public var sessionKeys: CoseKeyExchange
    /** Raw CBOR bytes of DeviceEngagement (NOT tag-24 wrapped). */
    public var deviceEngagementRawData: Array<UInt8>
    /** Raw CBOR bytes of the eReaderKey map (NOT tag-24 wrapped). */
    public let eReaderKeyRawData: Array<UInt8>
    /** Pre-encoded CBOR bytes of the handover value. */
    public let handOverBytes: Array<UInt8>

    // Nonce identifiers per ISO 18013-5 §9.1.1.5
    static let IDENTIFIER0: Array<UInt8> = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8]
    static let IDENTIFIER1: Array<UInt8> = [0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 1u8]

    public init(
        sessionRole: SessionRole,
        sessionKeys: CoseKeyExchange,
        deviceEngagementRawData: Array<UInt8>,
        eReaderKeyRawData: Array<UInt8>,
        handOverBytes: Array<UInt8>
    ) {
        this.sessionRole = sessionRole
        this.deviceCounter = UInt32(1)
        this.readerCounter = UInt32(1)
        this.keyAgreement = None
        this.cachedSharedSecret = None
        this.sessionKeys = sessionKeys
        this.deviceEngagementRawData = deviceEngagementRawData
        this.eReaderKeyRawData = eReaderKeyRawData
        this.handOverBytes = handOverBytes
    }

    /**
     * Encryption-side counter, kept for callers written against the single
     * iOS-style counter (mdoc role: the counter of SKDevice messages).
     */
    public mut prop sessionCounter: UInt32 {
        get() {
            this.deviceCounter
        }
        set(value) {
            this.deviceCounter = value
        }
    }

    /**
     * Replace the key exchange pair and drop the cached shared secret.
     */
    public func setSessionKeys(keys: CoseKeyExchange): Unit {
        this.sessionKeys = keys
        this.cachedSharedSecret = None
    }

    /**
     * Convenience constructor for the mdoc (holder/device) role.
     *
     * The device engagement provides the device's own key pair. The session
     * establishment provides the reader's ephemeral public key.
     *
     * iOS: SessionEncryption.init?(se:de:handOver:)
     */
    public static func forMdoc(
        eReaderKey: CoseKey,
        eReaderKeyRawData: Array<UInt8>,
        devicePrivateKey: CoseKeyPrivate,
        deviceEngagementRawData: Array<UInt8>,
        handOverBytes: Array<UInt8>
    ): SessionEncryption {
        let keys = CoseKeyExchange(Some(eReaderKey), devicePrivateKey)
        return SessionEncryption(
            Mdoc,
            keys,
            deviceEngagementRawData,
            eReaderKeyRawData,
            handOverBytes
        )
    }

    /**
     * The SessionTranscript for this session.
     * iOS: sessionTranscript
     */
    public func sessionTranscript(): SessionTranscript {
        return SessionTranscript(
            Some(deviceEngagementRawData),
            Some(eReaderKeyRawData),
            handOverBytes
        )
    }

    /**
     * The canonical SessionTranscriptBytes used as HKDF salt.
     * iOS: sessionTranscriptBytes
     */
    public func sessionTranscriptBytes(): Array<UInt8> {
        return this.sessionTranscript().toTaggedBytes()
    }

    /**
     * Identifier bytes for encryption operations.
     * mdoc role encrypts with IDENTIFIER1.
     */
    func encryptionIdentifier(): Array<UInt8> {
        return SessionEncryption.IDENTIFIER1
    }

    /**
     * Identifier bytes for decryption operations.
     * mdoc role decrypts with IDENTIFIER0.
     */
    func decryptionIdentifier(): Array<UInt8> {
        return SessionEncryption.IDENTIFIER0
    }

    /**
     * Build the 12-byte nonce = identifier(8B) || counter(4B big-endian).
     * iOS: makeNonce(_:isEncrypt:)
     */
    func makeNonce(counter: UInt32, isEncrypt: Bool): Array<UInt8> {
        let identifier = if (isEncrypt) {
            this.encryptionIdentifier()
        } else {
            this.decryptionIdentifier()
        }
        let counterBytes = uint32ToBigEndian(counter)
        let nonce = Array<UInt8>(12, repeat: 0)
        var i: Int64 = 0
        while (i < 8) {
            nonce[i] = identifier[i]
            i += 1
        }
        var j: Int64 = 0
        while (j < 4) {
            nonce[8 + j] = counterBytes[j]
            j += 1
        }
        return nonce
    }

    /**
     * HKDF info string for key derivation:
     *   - encrypt: "SKDevice" (mdoc encrypts with device key per §9.1.1)
     *   - decrypt: "SKReader" (mdoc decrypts reader's messages)
     *
     * iOS: getInfo(isEncrypt:)
     */
    func getInfo(isEncrypt: Bool): String {
        if (isEncrypt) {
            return "SKDevice"
        }
        return "SKReader"
    }

    /**
     * Perform ECKA-DH key agreement and derive a session key.
     *
     * 1. Extract peer public key (CoseKey.x, CoseKey.y) → build HUKS DER format.
     * 2. Call EcdhP256.agree(privateKeyAlias, peerPublicKeyDer) → sharedSecretBytes.
     * 3. Derive session key: HKDF(salt=sessionTranscriptBytes, ikm=sharedSecret,
     *                              info=UTF8("SKDevice"|"SKReader"), length=32).
     *
     * iOS: makeKeyAgreementAndDeriveSessionKey(isEncrypt:)
     */
    func makeKeyAgreementAndDeriveSessionKey(isEncrypt: Bool): Array<UInt8> {
        let sharedSecret = this.makeEckaDHAgreement()
        let salt = this.sessionTranscriptBytes()
        let infoStr = this.getInfo(isEncrypt)
        let info = stringToUtf8Bytes(infoStr)
        return Hkdf.derive(salt, sharedSecret, info, 32)
    }

    /**
     * Encrypt plaintext data using the current session counter.
     *
     * Returns ciphertext with the 16-byte GCM auth tag appended.
     * After encryption the session counter is incremented.
     *
     * iOS: encrypt(_:) async throws -> [UInt8]?
     */
    public func encrypt(data: Array<UInt8>): Array<UInt8> {
        let nonce = this.makeNonce(deviceCounter, true)
        let sessionKey = this.makeKeyAgreementAndDeriveSessionKey(true)
        let emptyAad = Array<UInt8>()
        let ciphertext = AesGcm.seal(sessionKey, nonce, emptyAad, data)
        deviceCounter += UInt32(1)
        return ciphertext
    }

    /**
     * Decrypt ciphertext (with appended 16-byte GCM tag) using the current
     * session counter.
     *
     * Returns Some(plaintext) on success; None on authentication failure.
     * After decryption the session counter is incremented.
     *
     * iOS: decrypt(_:) async throws -> [UInt8]
     */
    public func decrypt(ciphertextAndTag: Array<UInt8>): ?Array<UInt8> {
        let nonce = this.makeNonce(readerCounter, false)
        let sessionKey = this.makeKeyAgreementAndDeriveSessionKey(false)
        let emptyAad = Array<UInt8>()
        let result = AesGcm.open(sessionKey, nonce, emptyAad, ciphertextAndTag)
        readerCounter += UInt32(1)
        return result
    }

    /**
     * Compute ECDH shared secret bytes from the current key exchange pair.
     * Exposed for testing and for the device_auth feature (EMacKey derivation).
     *
     * iOS: makeEckaDHAgreement (in EckaDHAgreement.swift)
     */
    public func makeEckaDHAgreement(): Array<UInt8> {
        match (this.cachedSharedSecret) {
            case Some(secret) => return secret
            case None => ()
        }
        let peerPublicKeyOpt = sessionKeys.publicKey
        let peerPublicKey: CoseKey = match (peerPublicKeyOpt) {
            case Some(k) => k
            case None => throw CoreCryptoException("makeEckaDHAgreement: peer public key missing")
        }
        let secret: Array<UInt8> = match (this.keyAgreement) {
            case Some(provider) =>
                provider.agree(buildP256X963PublicKey(peerPublicKey.x, peerPublicKey.y))
            case None =>
                let peerDer = buildP256DerPublicKey(peerPublicKey.x, peerPublicKey.y)
                let privateKeyAlias = sessionKeys.privateKey.privateKeyId
                EcdhP256.agree(privateKeyAlias, peerDer)
        }
        this.cachedSharedSecret = Some(secret)
        return secret
    }

    /**
     * Derive a session key from a shared secret using HKDF-SHA256.
     *
     * salt   = SessionTranscriptBytes
     * ikm    = sharedSecret (from ECDH)
     * info   = UTF-8 bytes of infoString ("SKDevice", "SKReader", or "EMacKey")
     * length = 32 (256-bit output)
     *
     * Exposed statically for use by the device_auth feature.
     * iOS: HMACKeyDerivationFunction(sharedSecret:salt:info:)
     */
    public static func hkdfDeriveKey(
        sharedSecret: Array<UInt8>,
        salt: Array<UInt8>,
        info: Array<UInt8>
    ): Array<UInt8> {
        return Hkdf.derive(salt, sharedSecret, info, 32)
    }
}
