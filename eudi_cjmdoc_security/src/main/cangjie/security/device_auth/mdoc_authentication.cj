/*
 * mdoc_authentication.cj — ISO 18013-5 §9.1.3 device authentication.
 *
 * Implements:
 *   - DeviceAuthMethod enum (deviceSignature / deviceMac)
 *   - DeviceAuthentication CBOR structure (§9.1.3.1)
 *   - CoseMac0 — detached COSE_Mac0 value type
 *   - MdocAuthentication — EMacKey derivation + COSE_Sign1/Mac0 construction
 *
 * Device authentication provides proof of possession of the mDoc private key.
 * Two methods are supported:
 *   deviceSignature — COSE_Sign1 signed with the static device key (ES256)
 *   deviceMac       — COSE_Mac0 MACed with EMacKey derived from ECDH + HKDF
 *
 * DeviceAuthentication CBOR (§9.1.3.1):
 *   ["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]
 *   where DeviceNameSpacesBytes = Tag24(encoded(DeviceNameSpaces)) per spec.
 *
 * The COSE payload used for signing/MACing is:
 *   DeviceAuthenticationBytes = Tag24(encoded(DeviceAuthentication))
 * This payload is DETACHED in both COSE_Sign1 and COSE_Mac0 structures.
 *
 * EMacKey derivation (§9.1.3.1):
 *   EMacKey = HKDF(
 *     salt  = SessionTranscriptBytes,
 *     ikm   = ECDH-SharedSecret(SDeviceKey.Priv, EReaderKey.Pub),
 *     info  = "EMacKey",
 *     len   = 32
 *   )
 *
 * COSE_Mac0 MAC_Structure (RFC 8152 §6.3):
 *   MAC_Structure = ["MAC0", protected_header_bytes, "", payload_bytes]
 *   MAC value = HMAC-SHA256(EMacKey, MAC_Structure_bytes)
 *
 * COSE_Sign1 Sig_Structure is delegated to CoseSign1.sigStructureBytes() which
 * follows RFC 8152 §4.4:
 *   Sig_Structure = ["Signature1", protected_header_bytes, "", payload_bytes]
 *
 * CBOR encoding: all CBOR uses ohos_app_cangjie_eudi_cjcbor library.
 * CBOR / Tag24: TaggedVal(CborTag.ENCODED_CBOR, ByteStringVal(b)) — single layer,
 * per R-109 / session Tag24 pattern already established.
 *
 * iOS sources mirrored:
 *   Sources/MdocSecurity18013/MdocAuthentication/MdocAuthentication.swift
 *   Sources/MdocSecurity18013/MdocAuthentication/DeviceAuthentication.swift
 *   Sources/MdocSecurity18013/MdocAuthentication/CoseMAC.swift
 *   Sources/MdocSecurity18013/MdocAuthentication/CoseSignature.swift
 */
package ohos_app_cangjie_eudi_cjmdoc_security.security.device_auth

import std.collection.ArrayList

import stdx.crypto.keys.ECDSAPrivateKey
import stdx.crypto.keys.ECDSAPublicKey

import eudi_lib_core_crypto.EcdsaP256
import eudi_lib_core_crypto.Hmac

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.engagement.CoseKeyExchange
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.core.CoseSign1
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.core.CoseHeader
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.core.VerifyAlgorithm
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.core.MacAlgorithm
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.core.MdocValidationError

import ohos_app_cangjie_eudi_cjcbor.cbor.CborValue
import ohos_app_cangjie_eudi_cjcbor.cbor.CborTag
import ohos_app_cangjie_eudi_cjcbor.cbor.decodeCbor

import ohos_app_cangjie_eudi_cjmdoc_security.security.session.SessionTranscript
import ohos_app_cangjie_eudi_cjmdoc_security.security.session.SessionEncryption

/* ==================================================================== */
/* DeviceAuthMethod — selects COSE_Sign1 vs COSE_Mac0                   */
/* ==================================================================== */

/**
 * The device authentication method to use.
 *
 * - DeviceSignature: COSE_Sign1 signed with the static device key (ES256).
 * - DeviceMac:       COSE_Mac0 MACed with the ephemeral EMacKey (HMAC-256).
 *   DeviceMac is the preferred method (§9.1.3.1 NOTE).
 *
 * iOS: DeviceAuthMethod enum in DeviceAuthentication.swift
 */
public enum DeviceAuthMethod {
    /** Static device key COSE_Sign1 (ES256). */
    | DeviceSignature
    /** Ephemeral EMacKey COSE_Mac0 (HMAC-SHA256). */
    | DeviceMac
}

/* ==================================================================== */
/* CoseMac0 — detached COSE_Mac0 value                                  */
/* ==================================================================== */

/**
 * A detached COSE_Mac0 structure (no outer tag 9).
 *
 * Wire: [protected_bstr, {}, nil, tag_bstr]
 *   protected_bstr — encoded header map {"alg": 5 (HMAC-256)}
 *   {} — empty unprotected header map
 *   nil — detached payload (null)
 *   tag_bstr — 32-byte HMAC-SHA256 output
 *
 * RFC 8152 §6.1: COSE_Mac0 tag = 17; in ISO 18013-5 the structure is
 * typically embedded as-is inside DeviceAuth without the outer tag.
 */
public class CoseMac0 {
    /** Raw bytes of the encoded protected header map. */
    public let protectedHeaderBytes: Array<UInt8>
    /** The 32-byte MAC tag (HMAC-SHA256). */
    public let tag: Array<UInt8>

    public init(protectedHeaderBytes: Array<UInt8>, tag: Array<UInt8>) {
        this.protectedHeaderBytes = protectedHeaderBytes
        this.tag = tag
    }

    /**
     * Encode as a 4-element CBOR array (no outer tag).
     * [bstr(protected), {}, null, bstr(tag)]
     */
    public func toCborArray(): CborValue {
        let items = ArrayList<CborValue>()
        items.add(CborValue.ByteStringVal(protectedHeaderBytes))
        // Empty unprotected header
        let emptyPairs = ArrayList<(CborValue, CborValue)>()
        items.add(CborValue.MapVal(emptyPairs))
        // Detached payload = null
        items.add(CborValue.NullVal)
        // Tag bytes
        items.add(CborValue.ByteStringVal(tag))
        return CborValue.ArrayVal(items)
    }

    /**
     * Encode as raw CBOR bytes (4-element array without outer COSE_Mac0 tag 17).
     */
    public func toCborBytes(): Array<UInt8> {
        return this.toCborArray().encode()
    }
}

/* ==================================================================== */
/* DeviceAuthentication — §9.1.3.1 intermediate structure               */
/* ==================================================================== */

/**
 * DeviceAuthentication CBOR intermediate structure (§9.1.3.1).
 *
 * This structure is not transferred on the wire; it is only computed locally.
 * Its CBOR encoding is:
 *   ["DeviceAuthentication", SessionTranscript, docType, DeviceNameSpacesBytes]
 *   where DeviceNameSpacesBytes = Tag24(bytes(DeviceNameSpaces)).
 *
 * The actual COSE payload is DeviceAuthenticationBytes = Tag24(bytes(this)).
 *
 * iOS: DeviceAuthentication struct in DeviceAuthentication.swift
 */
public class DeviceAuthentication {
    /** Session transcript for this authentication. */
    public let sessionTranscript: SessionTranscript
    /** Document type string (e.g. "org.iso.18013.5.1.mDL"). */
    public let docType: String
    /**
     * Pre-encoded bytes of DeviceNameSpaces (e.g. CBOR empty map 0xA0).
     * These bytes are wrapped in Tag24 inside the DeviceAuthentication array.
     */
    public let deviceNameSpacesBytes: Array<UInt8>

    /**
     * Create a DeviceAuthentication.
     *
     * @param sessionTranscript  The session transcript.
     * @param docType            The mDoc document type string.
     * @param deviceNameSpacesBytes  Pre-encoded DeviceNameSpaces CBOR bytes.
     *   Pass [0xA0] for an empty DeviceNameSpaces map (most common case).
     */
    public init(
        sessionTranscript: SessionTranscript,
        docType: String,
        deviceNameSpacesBytes: Array<UInt8>
    ) {
        this.sessionTranscript = sessionTranscript
        this.docType = docType
        this.deviceNameSpacesBytes = deviceNameSpacesBytes
    }

    /**
     * Encode the DeviceAuthentication array as CBOR bytes.
     *
     * ["DeviceAuthentication", SessionTranscript, docType, Tag24(deviceNameSpacesBytes)]
     *
     * SessionTranscript is encoded as its CBOR value (array of 3) — not tag-24 wrapped here;
     * the outer toCborBytes will be passed to toTaggedBytes() for the Tag24 wrapping.
     *
     * iOS: toCBOR in DeviceAuthentication.swift
     */
    public func toCborBytes(): Array<UInt8> {
        let items = ArrayList<CborValue>()
        // [0] "DeviceAuthentication" label
        items.add(CborValue.TextStringVal("DeviceAuthentication"))
        // [1] SessionTranscript as CBOR array(3)
        let stBytes = sessionTranscript.toCborBytes()
        items.add(decodeCbor(stBytes))
        // [2] docType string
        items.add(CborValue.TextStringVal(docType))
        // [3] DeviceNameSpacesBytes = Tag24(deviceNameSpacesBytes)
        items.add(CborValue.TaggedVal(CborTag.ENCODED_CBOR, CborValue.ByteStringVal(deviceNameSpacesBytes)))
        return CborValue.ArrayVal(items).encode()
    }

    /**
     * DeviceAuthenticationBytes = Tag24(encoded(DeviceAuthentication)).
     * This is the DETACHED payload for COSE_Sign1 / COSE_Mac0.
     *
     * iOS: toCBOR.taggedEncoded.encode()
     */
    public func toTaggedBytes(): Array<UInt8> {
        return CborValue.TaggedVal(
            CborTag.ENCODED_CBOR,
            CborValue.ByteStringVal(this.toCborBytes())
        ).encode()
    }
}

/* ==================================================================== */
/* MdocAuthentication — device auth main class                          */
/* ==================================================================== */

/**
 * Implements ISO 18013-5 §9.1.3 mDoc device authentication.
 *
 * Two authentication methods are provided:
 *   - COSE_Sign1 (deviceSignature): signed with the static device key via EcdsaP256.
 *   - COSE_Mac0 (deviceMac): MACed with the ephemeral EMacKey derived via HKDF.
 *
 * Both methods use a DETACHED payload: DeviceAuthenticationBytes = Tag24(DeviceAuthentication).
 *
 * iOS: MdocAuthentication struct in MdocAuthentication.swift
 */
public class MdocAuthentication {
    /** Session transcript for this session. */
    public let sessionTranscript: SessionTranscript
    /** ECDH key exchange pair (peer public key + device private key). */
    public let authKeys: CoseKeyExchange

    /**
     * Create an MdocAuthentication.
     *
     * @param sessionTranscript  Session transcript from SessionEncryption.
     * @param authKeys           Key exchange pair: authKeys.publicKey is the reader's
     *                           ephemeral public key; authKeys.privateKey is the device's key.
     *
     * iOS: init(transcript:authKeys:)
     */
    public init(sessionTranscript: SessionTranscript, authKeys: CoseKeyExchange) {
        this.sessionTranscript = sessionTranscript
        this.authKeys = authKeys
    }

    /**
     * Derive the ephemeral EMacKey for COSE_Mac0 device authentication (§9.1.3.1).
     *
     * EMacKey = HKDF(
     *   salt  = SessionTranscriptBytes (Tag24 of SessionTranscript),
     *   ikm   = ECDH shared secret (SDeviceKey.Priv, EReaderKey.Pub),
     *   info  = UTF-8("EMacKey"),
     *   len   = 32
     * )
     *
     * Reuses SessionEncryption.hkdfDeriveKey() — same HKDF primitive used for
     * SKDevice/SKReader derivation. The only difference is the info string.
     *
     * @param sharedSecret     Raw ECDH shared secret bytes (from ECDH agreement).
     * @param saltBytes        SessionTranscriptBytes (Tag24 encoded).
     * @return                 32-byte EMacKey.
     *
     * iOS: makeMACKeyAggrementAndDeriveKey — HMACKeyDerivationFunction call
     */
    public static func deriveEMacKey(
        sharedSecret: Array<UInt8>,
        saltBytes: Array<UInt8>
    ): Array<UInt8> {
        // info = UTF-8("EMacKey") = [0x45, 0x4D, 0x61, 0x63, 0x4B, 0x65, 0x79]
        let info: Array<UInt8> = [0x45u8, 0x4Du8, 0x61u8, 0x63u8, 0x4Bu8, 0x65u8, 0x79u8]
        return SessionEncryption.hkdfDeriveKey(sharedSecret, saltBytes, info)
    }

    /**
     * Build the MAC_Structure bytes for COSE_Mac0 per RFC 8152 §6.3.
     *
     * MAC_Structure = [
     *   "MAC0",                  -- context
     *   bstr(protectedHeader),   -- protected header bytes
     *   bstr(""),                -- empty external AAD
     *   bstr(payload)            -- the detached payload bytes
     * ]
     *
     * @param protectedHeaderBytes  Encoded protected header bytes (contains alg=5).
     * @param payloadBytes          DeviceAuthenticationBytes (Tag24 of DeviceAuthentication).
     * @return Encoded MAC_Structure bytes.
     */
    static func buildMacStructureBytes(
        protectedHeaderBytes: Array<UInt8>,
        payloadBytes: Array<UInt8>
    ): Array<UInt8> {
        let items = ArrayList<CborValue>()
        items.add(CborValue.TextStringVal("MAC0"))
        items.add(CborValue.ByteStringVal(protectedHeaderBytes))
        items.add(CborValue.ByteStringVal(Array<UInt8>()))   // empty external AAD
        items.add(CborValue.ByteStringVal(payloadBytes))
        return CborValue.ArrayVal(items).encode()
    }

    /**
     * Construct a detached COSE_Mac0 over DeviceAuthenticationBytes (§9.1.3.1).
     *
     * Steps:
     *   1. Build protected header: {1: 5} (alg = HMAC-256)
     *   2. Build MAC_Structure from ["MAC0", phBytes, "", payloadBytes]
     *   3. Compute HMAC-SHA256(emacKey, MAC_Structure_bytes) → tag
     *   4. Return CoseMac0(phBytes, tag) with detached payload (nil in wire)
     *
     * @param payloadBytes   DeviceAuthenticationBytes (toTaggedBytes() output).
     * @param emacKey        32-byte ephemeral MAC key.
     * @return               Detached CoseMac0.
     *
     * iOS: Cose.makeDetachedCoseMac0 in CoseMAC.swift
     */
    public static func makeDetachedCoseMac0(
        payloadBytes: Array<UInt8>,
        emacKey: Array<UInt8>
    ): CoseMac0 {
        // Protected header: {1: 5} (alg = Hmac256 = COSE value 5)
        let ph = CoseHeader.build(MacAlgorithm.Hmac256.coseValue(), false, None)
        let phBytes: Array<UInt8> = match (ph.rawHeaderBytes) {
            case Some(b) => b
            case None => throw MdocValidationError.invalidCbor("CoseMac0: protected header missing")
        }
        // MAC_Structure
        let macStructBytes = buildMacStructureBytes(phBytes, payloadBytes)
        // HMAC-SHA256
        let tagBytes = Hmac.sha256(emacKey, macStructBytes)
        return CoseMac0(phBytes, tagBytes)
    }

    /**
     * Verify a detached COSE_Mac0 tag against a recomputed MAC.
     *
     * Recomputes MAC_Structure and verifies HMAC-SHA256 output matches the stored tag.
     *
     * @param mac0           The CoseMac0 to verify.
     * @param payloadBytes   The original DeviceAuthenticationBytes (detached payload).
     * @param emacKey        The same EMacKey used to create the MAC.
     * @return               True if the tag is valid; false otherwise.
     *
     * iOS: Cose.computeMACValue for verification (caller compares)
     */
    public static func verifyDetachedCoseMac0(
        mac0: CoseMac0,
        payloadBytes: Array<UInt8>,
        emacKey: Array<UInt8>
    ): Bool {
        let macStructBytes = buildMacStructureBytes(mac0.protectedHeaderBytes, payloadBytes)
        let expectedTag = Hmac.sha256(emacKey, macStructBytes)
        return bytesEqual(expectedTag, mac0.tag)
    }

    /**
     * Construct a detached COSE_Sign1 over DeviceAuthenticationBytes (§9.1.3.1).
     *
     * Steps:
     *   1. Build protected header: {1: -7} (alg = ES256)
     *   2. Build CoseSign1 with detached payload (payload = None in Sig_Structure, payload = payloadBytes for signing)
     *   3. Compute Sig_Structure bytes by temporarily attaching the payload
     *   4. Sign Sig_Structure with EcdsaP256 (raw r||s format, 64 bytes)
     *   5. Return CoseSign1 with detached payload (payload = None)
     *
     * Note: The device private key in production uses HUKS (via CoseKeyPrivate.privateKeyId alias).
     * Here we accept an ECDSAPrivateKey directly — callers that use HUKS must adapt accordingly
     * via a secure area abstraction. For the current feature scope (software-backed keys in tests
     * and host builds), this suffices per the same pattern as SoftwareSecureArea.
     *
     * @param payloadBytes   DeviceAuthenticationBytes (toTaggedBytes() output).
     * @param privateKey     stdx ECDSAPrivateKey for ES256.
     * @return               Detached CoseSign1.
     *
     * iOS: Cose.makeDetachedCoseSign1 in CoseSignature.swift
     */
    public static func makeDetachedCoseSign1(
        payloadBytes: Array<UInt8>,
        privateKey: ECDSAPrivateKey
    ): CoseSign1 {
        // Protected header: {1: -7} (alg = ES256)
        let algValue = VerifyAlgorithm.Es256.coseValue()   // -7
        // Build CoseSign1 with payload attached first to get Sig_Structure
        let coseWithPayload = CoseSign1.create(algValue, Some(payloadBytes), None, Array<UInt8>())
        let sigStructBytesOpt = coseWithPayload.sigStructureBytes()
        let sigStructBytes: Array<UInt8> = match (sigStructBytesOpt) {
            case Some(b) => b
            case None => throw MdocValidationError.invalidCbor("CoseSign1: cannot compute Sig_Structure")
        }
        // ES256 sign: raw r||s (64 bytes)
        let rawSig = EcdsaP256.sign(privateKey, sigStructBytes)
        // Return CoseSign1 with DETACHED payload (payload = None)
        return CoseSign1.create(algValue, None, None, rawSig)
    }

    /**
     * Construct a detached COSE_Sign1 over DeviceAuthenticationBytes with an
     * external ES256 signer — the seam for keys that never leave a
     * SecureArea (HUKS): the signer receives the Sig_Structure bytes and
     * returns the raw r||s signature (64 bytes).
     *
     * @param payloadBytes   DeviceAuthenticationBytes (toTaggedBytes() output).
     * @param signer         ES256 signer over the Sig_Structure bytes.
     * @return               Detached CoseSign1.
     *
     * iOS: Cose.makeDetachedCoseSign1 with CoseKeyPrivate.secureArea.signature
     */
    public static func makeDetachedCoseSign1WithSigner(
        payloadBytes: Array<UInt8>,
        signer: (Array<UInt8>) -> Array<UInt8>
    ): CoseSign1 {
        let algValue = VerifyAlgorithm.Es256.coseValue()
        let coseWithPayload = CoseSign1.create(algValue, Some(payloadBytes), None, Array<UInt8>())
        let sigStructBytes: Array<UInt8> = match (coseWithPayload.sigStructureBytes()) {
            case Some(b) => b
            case None => throw MdocValidationError.invalidCbor("CoseSign1: cannot compute Sig_Structure")
        }
        let rawSig = signer(sigStructBytes)
        return CoseSign1.create(algValue, None, None, rawSig)
    }

    /**
     * DeviceAuth (deviceSignature) for transfer, signed through an external
     * ES256 signer (SecureArea-resident device key).
     *
     * @param docType                Document type string.
     * @param deviceNameSpacesBytes  Pre-encoded DeviceNameSpaces CBOR bytes.
     * @param signer                 ES256 signer over the Sig_Structure bytes.
     */
    public func makeDeviceSignatureWithSigner(
        docType: String,
        deviceNameSpacesBytes: Array<UInt8>,
        signer: (Array<UInt8>) -> Array<UInt8>
    ): CoseSign1 {
        let deviceAuth = DeviceAuthentication(sessionTranscript, docType, deviceNameSpacesBytes)
        return MdocAuthentication.makeDetachedCoseSign1WithSigner(deviceAuth.toTaggedBytes(), signer)
    }

    /**
     * DeviceAuth (deviceMac) for transfer from an already computed ECDH
     * shared secret (SecureArea keyAgreement of the document device key with
     * EReaderKey): EMacKey = HKDF(salt = SessionTranscriptBytes, ikm =
     * sharedSecret, info = "EMacKey"), then a detached COSE_Mac0.
     */
    public func makeDeviceMac(
        docType: String,
        deviceNameSpacesBytes: Array<UInt8>,
        sharedSecret: Array<UInt8>
    ): CoseMac0 {
        let deviceAuth = DeviceAuthentication(sessionTranscript, docType, deviceNameSpacesBytes)
        let saltBytes = sessionTranscript.toTaggedBytes()
        let emacKey = MdocAuthentication.deriveEMacKey(sharedSecret, saltBytes)
        return MdocAuthentication.makeDetachedCoseMac0(deviceAuth.toTaggedBytes(), emacKey)
    }

    /**
     * Verify a detached COSE_Sign1 signature.
     *
     * Reattaches the payload, recomputes Sig_Structure, and verifies ES256 signature.
     *
     * @param sign1          The CoseSign1 to verify (must have detached payload = None).
     * @param payloadBytes   The original DeviceAuthenticationBytes.
     * @param publicKey      The device's ECDSA public key.
     * @return               True if the signature is valid; false otherwise.
     *
     * iOS: Cose.validateDetachedCoseSign1 in CoseSignature.swift
     */
    public static func verifyDetachedCoseSign1(
        sign1: CoseSign1,
        payloadBytes: Array<UInt8>,
        publicKey: ECDSAPublicKey
    ): Bool {
        // Reattach payload to compute Sig_Structure
        let algValue = match (sign1.protectedHeader.algorithm) {
            case Some(a) => a
            case None => return false
        }
        let coseWithPayload = CoseSign1.create(algValue, Some(payloadBytes), None, Array<UInt8>())
        let sigStructBytesOpt = coseWithPayload.sigStructureBytes()
        let sigStructBytes: Array<UInt8> = match (sigStructBytesOpt) {
            case Some(b) => b
            case None => return false
        }
        return EcdsaP256.verify(publicKey, sigStructBytes, sign1.signature)
    }

    /**
     * Get the DeviceAuth structure for transfer.
     *
     * Constructs a DeviceAuthentication CBOR structure and produces either a
     * COSE_Sign1 or COSE_Mac0 based on the requested authentication method.
     *
     * For DeviceMac, the ECDH shared secret must already have been computed by
     * the caller (e.g. via SessionEncryption.makeEckaDHAgreement()) and the
     * EMacKey derived using deriveEMacKey().
     *
     * @param docType                Document type string.
     * @param dauthMethod            Authentication method.
     * @param deviceNameSpacesBytes  Pre-encoded DeviceNameSpaces CBOR bytes ([0xA0] for empty).
     * @param sharedSecret           ECDH shared secret bytes (required for DeviceMac; pass [] for DeviceSignature).
     * @param devicePrivateKey       Device private key (required for DeviceSignature).
     * @return A tuple of (CoseSign1-or-nil, CoseMac0-or-nil) — exactly one is Some.
     *
     * iOS: getDeviceAuthForTransfer in MdocAuthentication.swift
     */
    public func getDeviceAuthForTransfer(
        docType: String,
        dauthMethod: DeviceAuthMethod,
        deviceNameSpacesBytes: Array<UInt8>,
        sharedSecret: Array<UInt8>,
        devicePrivateKey: ?ECDSAPrivateKey
    ): (?CoseSign1, ?CoseMac0) {
        let deviceAuth = DeviceAuthentication(
            sessionTranscript,
            docType,
            deviceNameSpacesBytes
        )
        let payloadBytes = deviceAuth.toTaggedBytes()
        match (dauthMethod) {
            case DeviceSignature =>
                let privKey: ECDSAPrivateKey = match (devicePrivateKey) {
                    case Some(k) => k
                    case None => throw MdocValidationError.invalidCbor("DeviceSignature: device private key required")
                }
                let sign1 = MdocAuthentication.makeDetachedCoseSign1(payloadBytes, privKey)
                let noMac0: ?CoseMac0 = None
                return (Some(sign1), noMac0)
            case DeviceMac =>
                let saltBytes = sessionTranscript.toTaggedBytes()
                let emacKey = MdocAuthentication.deriveEMacKey(sharedSecret, saltBytes)
                let mac0 = MdocAuthentication.makeDetachedCoseMac0(payloadBytes, emacKey)
                let noSign1: ?CoseSign1 = None
                return (noSign1, Some(mac0))
        }
    }
}

/* ==================================================================== */
/* Internal byte comparison helper                                        */
/* ==================================================================== */

/**
 * Constant-time-ish byte array comparison.
 * Not true constant-time but sufficient for test and MAC verification purposes.
 */
func bytesEqual(a: Array<UInt8>, b: Array<UInt8>): Bool {
    if (a.size != b.size) {
        return false
    }
    var i: Int64 = 0
    while (i < a.size) {
        if (a[i] != b[i]) {
            return false
        }
        i += 1
    }
    return true
}
