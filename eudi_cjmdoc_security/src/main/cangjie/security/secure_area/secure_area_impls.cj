/*
 * secure_area_impls.cj
 *
 * Concrete SecureArea implementations for the eudi_cjmdoc_security module:
 *   - SoftwareSecureArea: pure-software P-256 keys via stdx.crypto.keys (EcdsaP256 from core-crypto)
 *   - HuksSecureArea:     hardware-backed P-256 keys via HUKS alias scheme (kit.UniversalKeystoreKit)
 *
 * Thread-safety contract (inherited from SecureArea interface doc):
 *   iOS SecureArea/SecureKeyStorage are Swift Actors with implicit serial-executor isolation.
 *   In Cangjie there is no Actor keyword; implementors are responsible for managing their own
 *   thread safety. Both classes below document this contract via comment; callers needing strict
 *   concurrent access must synchronize externally (or use a single-threaded context).
 *
 * x963 public-key format:
 *   Uncompressed EC point: 0x04 || X (32B) || Y (32B) = 65 bytes for P-256.
 *   extractX963FromDer() uses TLV parsing via readSpkiDerLength — no hardcoded byte offsets.
 *   For a standard 91-byte P-256 SPKI the uncompressed point (0x04||X||Y) is found at DER offset 26,
 *   but TLV parsing handles any conformant SPKI.
 *
 * Storage layout for SoftwareSecureArea (keys in SecureKeyStorage):
 *   key "privDer_<index>" -> PKCS#8 DER bytes of ECDSAPrivateKey (stored in per-index keyInfo slot)
 *   key "pubX963_<index>" -> 65-byte uncompressed EC point (x963 public key, same slot)
 *   key "kbiBytes"        -> KeyBatchInfo CBOR bytes (in "<id>_meta" keyInfo slot)
 *
 * Storage layout for HuksSecureArea (keys managed inside HUKS):
 *   key "huksAlias_<index>" -> UTF-8 bytes of the HUKS key alias string
 *   key "huksPurpose_<index>" -> "agree" for key-agreement batches (absent = signing)
 *   key "pubX963_<index>"   -> 65-byte uncompressed EC point extracted from HUKS exportKeyItem
 *   key "kbiBytes"          -> KeyBatchInfo CBOR bytes (in "<id>_meta" keyInfo slot)
 *
 * iOS references:
 *   Sources/MdocSecurity18013/SecureAreaImplementations/SoftwareSecureArea.swift
 *   Sources/MdocSecurity18013/SecureAreaImplementations/SecureEnclaveSecureArea.swift
 */
package ohos_app_cangjie_eudi_cjmdoc_security.security.secure_area

import std.collection.HashMap
import std.collection.ArrayList
import kit.PerformanceAnalysisKit.Hilog
import kit.UniversalKeystoreKit.*
import stdx.crypto.keys.*
import stdx.crypto.common.*

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.SecureArea
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.SecureKeyStorage
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.SecureAreaError
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.CoseEcCurve
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.SigningAlgorithm
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.KeyOptions
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.CredentialOptions
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.CredentialPolicy
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.KeyPurpose
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.KeyBatchInfo

import eudi_lib_core_crypto.EcdsaP256
import eudi_lib_core_crypto.EcdhP256

import ohos_app_cangjie_eudi_cjmdoc_security.security.session.buildP256DerPublicKey

/* ====================================================================== */
/* Storage key helpers                                                      */
/* ====================================================================== */

/** Build a storage map-key string for a per-index slot. */
func storageKey(prefix: String, index: Int64): String {
    return prefix + "_" + index.toString()
}

/* ====================================================================== */
/* Curve check helpers (enums in Cangjie require match, not !=)            */
/* ====================================================================== */

/** Return true iff the curve is P256. */
func isP256(curve: CoseEcCurve): Bool {
    match (curve) {
        case CoseEcCurve.P256 => return true
        case _ => return false
    }
}

/** Return true iff the algorithm is ES256. */
func isES256(alg: SigningAlgorithm): Bool {
    match (alg) {
        case SigningAlgorithm.ES256 => return true
        case _ => return false
    }
}

/* ====================================================================== */
/* Key purpose helpers                                                      */
/* ====================================================================== */

/**
 * True iff the requested purposes are exactly key agreement (ECDH) and
 * nothing else. HarmonyOS HUKS rejects a key generated with SIGN|AGREE
 * ("gen key purpose not unique"), so a batch is either a signing batch
 * (default, document device keys) or an agreement batch (ephemeral
 * EDeviceKey for ISO 18013-5 session encryption).
 */
func isAgreementOnly(purposes: ?Array<KeyPurpose>): Bool {
    match (purposes) {
        case Some(list) =>
            if (list.size == 0) {
                return false
            }
            for (p in list) {
                match (p) {
                    case KeyPurpose.KeyAgreement => ()
                    case _ => return false
                }
            }
            return true
        case None => return false
    }
}

/**
 * HUKS ECDH takes the peer key in its exported form (X.509 SubjectPublicKeyInfo
 * DER). The SecureArea contract hands over a 65-byte x963 point, so wrap it;
 * a caller that already passes DER goes through unchanged.
 */
func huksPeerPublicKeyDer(publicKeyBytes: Array<UInt8>): Array<UInt8> {
    if (publicKeyBytes.size == 65 && publicKeyBytes[0] == UInt8(0x04)) {
        let x = Array<UInt8>(32, {i => publicKeyBytes[1 + i]})
        let y = Array<UInt8>(32, {i => publicKeyBytes[33 + i]})
        return buildP256DerPublicKey(x, y)
    }
    return publicKeyBytes
}

/* ====================================================================== */
/* x963 / DER conversion helpers                                           */
/* ====================================================================== */

/**
 * Extract an uncompressed EC point (x963, 65 bytes for P-256: 0x04||X||Y)
 * from an X.509 SubjectPublicKeyInfo DER blob produced by
 * ECDSAPublicKey.encodeToDer() or HUKS exportKeyItem().
 *
 * Parsing walks the DER TLV structure — no hardcoded byte offsets.
 * stdx EcdsaP256.generate() produces a 91-byte SPKI; HUKS may differ.
 *
 * DER layout (P-256):
 *   SEQUENCE {
 *     SEQUENCE { OID id-ecPublicKey, OID prime256v1 }   AlgorithmIdentifier
 *     BIT STRING { 0x00 unused-bits, 0x04 || X(32) || Y(32) }
 *   }
 *
 * Throws SecureAreaError if the structure is malformed or the key is not
 * an uncompressed (0x04-prefixed) EC point.
 */
/**
 * Read a DER length field at bytes[startOffset].
 * Supports short form (0-127, 1 byte) and long form (multi-byte).
 * Returns (length_value, new_offset_past_length_field).
 */
func readSpkiDerLength(bytes: Array<UInt8>, startOffset: Int64): (Int64, Int64) {
    if (startOffset >= bytes.size) {
        throw SecureAreaError("readSpkiDerLength: out of bounds at offset " + startOffset.toString())
    }
    let first = bytes[startOffset]
    if ((first & UInt8(0x80)) == UInt8(0)) {
        return (Int64(first), startOffset + 1)
    }
    let numBytes = Int64(first & UInt8(0x7F))
    if (numBytes == 0) {
        throw SecureAreaError("readSpkiDerLength: indefinite length not supported")
    }
    var len: Int64 = 0
    var i = startOffset + 1
    while (i < startOffset + 1 + numBytes) {
        if (i >= bytes.size) {
            throw SecureAreaError("readSpkiDerLength: out of bounds in multi-byte length")
        }
        len = (len << 8) | Int64(bytes[i])
        i++
    }
    return (len, startOffset + 1 + numBytes)
}

func extractX963FromDer(der: Array<UInt8>): Array<UInt8> {
    let n = der.size
    var offset: Int64 = 0

    // Outer SEQUENCE (tag 0x30)
    if (offset >= n || der[offset] != UInt8(0x30)) {
        throw SecureAreaError("extractX963FromDer: expected outer SEQUENCE (0x30)")
    }
    offset++
    let (_, off1) = readSpkiDerLength(der, offset)
    offset = off1

    // AlgorithmIdentifier SEQUENCE (tag 0x30) — skip entire TLV
    if (offset >= n || der[offset] != UInt8(0x30)) {
        throw SecureAreaError("extractX963FromDer: expected AlgorithmIdentifier SEQUENCE (0x30)")
    }
    offset++
    let (algLen, off2) = readSpkiDerLength(der, offset)
    offset = off2 + algLen

    // BIT STRING (tag 0x03)
    if (offset >= n || der[offset] != UInt8(0x03)) {
        throw SecureAreaError("extractX963FromDer: expected BIT STRING (0x03)")
    }
    offset++
    let (bitLen, off3) = readSpkiDerLength(der, offset)
    offset = off3
    if (bitLen < 2) {
        throw SecureAreaError("extractX963FromDer: BIT STRING too short (" + bitLen.toString() + ")")
    }
    // First byte = unused-bits count; always 0 for a full-byte EC point — skip it
    offset++
    let pointLen = bitLen - 1

    if (offset + pointLen > n) {
        throw SecureAreaError("extractX963FromDer: BIT STRING content out of bounds")
    }
    if (pointLen < 1 || der[offset] != UInt8(0x04)) {
        throw SecureAreaError("extractX963FromDer: expected 0x04 uncompressed point prefix")
    }
    let result = Array<UInt8>(pointLen, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < pointLen) {
        result[i] = der[offset + i]
        i++
    }
    return result
}

/**
 * Reconstruct an ECDSAPrivateKey from PKCS#8 DER bytes stored in the software
 * key storage ("privDer_<index>" slot).
 */
func loadPrivKeyFromDer(privDer: Array<UInt8>): ECDSAPrivateKey {
    let blob = DerBlob(privDer)
    return ECDSAPrivateKey.decodeDer(blob)
}

/* ====================================================================== */
/* SoftwareSecureArea                                                       */
/* ====================================================================== */

/**
 * Software-only SecureArea implementation using stdx.crypto.keys (P-256 ECDSA)
 * and HUKS-backed ECDH via eudi_lib_core_crypto.EcdhP256.
 *
 * Supported curves: P256 only (stdx.crypto.keys.ECDSAPrivateKey only exposes Curve.P256).
 * P384/P521 and other curves throw SecureAreaError("Unsupported curve").
 *
 * Thread-safety: callers must serialize concurrent access externally; this class
 * does not internally synchronize storage operations.
 *
 * Maps iOS SoftwareSecureArea (actor): async throws -> synchronous throws.
 */
public class SoftwareSecureArea <: SecureArea {

    private var storage: SecureKeyStorage

    /** The canonical name used for SecureAreaRegistry lookup. */
    public static let NAME: String = "Software"

    public init(storage: SecureKeyStorage) {
        this.storage = storage
    }

    /** Factory method (mirrors iOS nonisolated static func create). */
    public static func create(storage: SecureKeyStorage): SoftwareSecureArea {
        return SoftwareSecureArea(storage)
    }

    public func getName(): String {
        return SoftwareSecureArea.NAME
    }

    public func getDefaultEcCurve(): CoseEcCurve {
        return CoseEcCurve.P256
    }

    public func getSupportedEcCurves(): Array<CoseEcCurve> {
        return [CoseEcCurve.P256]
    }

    public func getStorage(): SecureKeyStorage {
        return this.storage
    }

    /**
     * Create a batch of P-256 key pairs.
     *
     * For each key in the batch:
     *   - Generates a fresh P-256 ECDSAPrivateKey via EcdsaP256.generate()
     *   - Stores PKCS#8 DER private key bytes under key "privDer_<i>"
     *   - Stores 65-byte uncompressed public key (x963) under key "pubX963_<i>"
     * Stores KeyBatchInfo CBOR bytes under key "kbiBytes" in the metadata slot.
     *
     * Mirrors iOS SoftwareSecureArea.createKeyBatch / createKeyMaterial.
     */
    public func createKeyBatch(
        id: String,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions
    ): KeyBatchInfo {
        let curve = match (keyOptions) {
            case Some(ko) => ko.curve
            case None => CoseEcCurve.P256
        }
        if (!isP256(curve)) {
            throw SecureAreaError("SoftwareSecureArea: unsupported curve " + curve.jwkName())
        }
        let batchSize = credentialOptions.batchSize
        let usedCounts = Array<Int64>(batchSize, {_ => Int64(0)})
        var i: Int64 = 0
        while (i < batchSize) {
            let privKey = EcdsaP256.generate()
            let pubKey = ECDSAPublicKey(privKey)
            let privDerBlob = privKey.encodeToDer()
            let pubDerBlob = pubKey.encodeToDer()
            let privDer = privDerBlob.body
            let pubDer = pubDerBlob.body
            let pubX963 = extractX963FromDer(pubDer)
            let slot = HashMap<String, Array<UInt8>>()
            slot[storageKey("privDer", i)] = privDer
            slot[storageKey("pubX963", i)] = pubX963
            this.storage.writeKeyInfo(storageKey(id, i), slot)
            i++
        }
        let kbi = KeyBatchInfo(
            Some(SoftwareSecureArea.NAME),
            CoseEcCurve.P256,
            usedCounts,
            credentialOptions.credentialPolicy,
            Some(KeyPurpose.allCases()),
            None
        )
        let kbiSlot = HashMap<String, Array<UInt8>>()
        kbiSlot["kbiBytes"] = kbi.toBytes()
        this.storage.writeKeyInfo(id + "_meta", kbiSlot)
        Hilog.info(0, "SecureArea", "SoftwareSecureArea.createKeyBatch id=" + id
            + " batchSize=" + batchSize.toString())
        return kbi
    }

    /**
     * Return the stored 65-byte uncompressed public key (x963) for the key at index.
     * The caller (e.g. session_encryption) wraps this into a CoseKey.
     */
    public func getPublicKeyBytes(id: String, index: Int64, curve: CoseEcCurve): Array<UInt8> {
        if (!isP256(curve)) {
            throw SecureAreaError("SoftwareSecureArea: unsupported curve " + curve.jwkName())
        }
        let slot = this.storage.readKeyInfo(storageKey(id, index))
        let slotKey = storageKey("pubX963", index)
        if (slot.contains(slotKey)) {
            return slot[slotKey]
        }
        throw SecureAreaError("SoftwareSecureArea.getPublicKeyBytes: no key for id=" + id
            + " index=" + index.toString())
    }

    /**
     * Software keys need no unlock; returns None.
     */
    public func unlockKey(id: String): ?Array<UInt8> {
        return None
    }

    /** Delete key data slots for the given batch slice. */
    public func deleteKeyBatch(id: String, startIndex: Int64, batchSize: Int64): Unit {
        var i = startIndex
        while (i < startIndex + batchSize) {
            this.storage.deleteKeyBatch(storageKey(id, i), 0, 1)
            i++
        }
    }

    /** Delete key metadata. */
    public func deleteKeyInfo(id: String): Unit {
        this.storage.deleteKeyInfo(id + "_meta")
    }

    /**
     * Compute an ES256 signature over dataToSign using the P-256 private key at index.
     *
     * Reads PKCS#8 DER from storage, reconstructs ECDSAPrivateKey, delegates to
     * EcdsaP256.sign() which SHA-256 hashes and returns raw r||s (64 bytes).
     *
     * Only SigningAlgorithm.ES256 is supported (P-256 curve).
     */
    public func signature(
        id: String,
        index: Int64,
        algorithm: SigningAlgorithm,
        dataToSign: Array<UInt8>,
        unlockData: ?Array<UInt8>
    ): Array<UInt8> {
        if (!isES256(algorithm)) {
            throw SecureAreaError(
                "SoftwareSecureArea: unsupported algorithm"
            )
        }
        let slot = this.storage.readKeyInfo(storageKey(id, index))
        let privDerKey = storageKey("privDer", index)
        if (!slot.contains(privDerKey)) {
            throw SecureAreaError(
                "SoftwareSecureArea.signature: no private key for id=" + id
                + " index=" + index.toString()
            )
        }
        let privDer = slot[privDerKey]
        let privKey = loadPrivKeyFromDer(privDer)
        let rawSig = EcdsaP256.sign(privKey, dataToSign)
        Hilog.info(0, "SecureArea", "SoftwareSecureArea.signature id=" + id
            + " index=" + index.toString())
        return rawSig
    }

    /**
     * Compute an ECDH P-256 shared secret between our private key and the remote public key.
     *
     * The remote public key bytes (publicKeyBytes) must be the 65-byte uncompressed x963 point
     * (0x04||X||Y). This method uses EcdhP256 from core-crypto which delegates to HUKS under
     * the hood, requiring a real device environment. It generates a transient HUKS P-256 key
     * under a transient alias, performs the ECDH agreement, then deletes the transient key.
     *
     * Returns raw shared secret bytes.
     *
     * Note: HUKS-backed ECDH is device-only; host-side unit tests for this method will fail
     * with a HUKS error. Software-side signing (above) is host-testable.
     */
    public func keyAgreement(
        id: String,
        index: Int64,
        publicKeyBytes: Array<UInt8>,
        unlockData: ?Array<UInt8>
    ): Array<UInt8> {
        let transientAlias = "sw_ka_" + id + "_" + index.toString()
        EcdhP256.generateKey(transientAlias)
        let sharedSecret: Array<UInt8>
        try {
            sharedSecret = EcdhP256.agree(transientAlias, huksPeerPublicKeyDer(publicKeyBytes))
        } catch (e: Exception) {
            EcdhP256.deleteKey(transientAlias)
            throw e
        }
        EcdhP256.deleteKey(transientAlias)
        Hilog.info(0, "SecureArea", "SoftwareSecureArea.keyAgreement id=" + id
            + " index=" + index.toString())
        return sharedSecret
    }

    /** Retrieve key batch metadata from storage. */
    public func getKeyBatchInfo(id: String): KeyBatchInfo {
        let metaSlot = this.storage.readKeyInfo(id + "_meta")
        if (!metaSlot.contains("kbiBytes")) {
            throw SecureAreaError(
                "SoftwareSecureArea.getKeyBatchInfo: no metadata for id=" + id
            )
        }
        return KeyBatchInfo.fromBytes(metaSlot["kbiBytes"])
    }

    /** Default signing algorithm for the given curve (ES256 for P-256). */
    public func defaultSigningAlgorithm(ecCurve: CoseEcCurve): SigningAlgorithm {
        return ecCurve.defaultSigningAlgorithm()
    }
}

/* ====================================================================== */
/* HuksSecureArea                                                           */
/* ====================================================================== */

/**
 * Hardware-backed SecureArea implementation using HUKS (kit.UniversalKeystoreKit).
 *
 * Maps iOS SecureEnclaveSecureArea (actor) to Cangjie class implementing SecureArea.
 * Only P-256 is supported (HUKS ECC_256 maps to P-256; HUKS does not expose P-384/P-521
 * for sign+agree combination in the current API level tested in ecdh.cj).
 *
 * Key lifecycle:
 *   createKeyBatch: generates HUKS ECC P-256 keys under aliases "eudi_sa_<id>_<i>",
 *                   exports public key (DER X.509) and converts to x963 (65B),
 *                   stores alias and public key bytes via SecureKeyStorage.
 *                   KeyOptions.keyPurposes == [KeyAgreement] yields a
 *                   HUKS_KEY_PURPOSE_AGREE key (ISO 18013-5 ephemeral EDeviceKey);
 *                   any other purpose set yields a SIGN key.
 *   signature:      init/finish HUKS sign session (ECDSA-SHA256).
 *   keyAgreement:   delegates to EcdhP256.agree() from core-crypto.
 *
 * Thread-safety: same contract as SoftwareSecureArea — implementors must manage externally.
 *
 * HUKS API note (verified from core-crypto ecdh.cj + KB cj-huks-signing-signature-verification.md):
 *   generateKeyItem / initSession / finishSession / exportKeyItem / deleteKeyItem
 *   are top-level functions from kit.UniversalKeystoreKit.
 */
public class HuksSecureArea <: SecureArea {

    private var storage: SecureKeyStorage

    /** The canonical name used for SecureAreaRegistry lookup. */
    public static let NAME: String = "HUKS"

    public init(storage: SecureKeyStorage) {
        this.storage = storage
    }

    /** Factory method. */
    public static func create(storage: SecureKeyStorage): HuksSecureArea {
        return HuksSecureArea(storage)
    }

    public func getName(): String {
        return HuksSecureArea.NAME
    }

    public func getDefaultEcCurve(): CoseEcCurve {
        return CoseEcCurve.P256
    }

    public func getSupportedEcCurves(): Array<CoseEcCurve> {
        return [CoseEcCurve.P256]
    }

    public func getStorage(): SecureKeyStorage {
        return this.storage
    }

    /**
     * Build a HUKS ECC P-256 sign key alias for this batch slot.
     * The alias must be stable across app restarts (so keys survive process death).
     */
    private func huksAlias(id: String, index: Int64): String {
        return "eudi_sa_" + id + "_" + index.toString()
    }

    /**
     * ECC P-256 SIGN properties. Optional CE/DE auth level and never-export
     * (HUKS_STORAGE_ONLY_USED_IN_HUKS) keep the private key inside HUKS,
     * matching iOS Secure Enclave non-exportable keys.
     */
    private func signGenerateProperties(authLevel: ?UInt32, neverExport: Bool): Array<HuksParam> {
        let list = ArrayList<HuksParam>()
        list.add(HuksParam(
            HuksTag.HUKS_TAG_ALGORITHM,
            HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_ECC)
        ))
        list.add(HuksParam(
            HuksTag.HUKS_TAG_KEY_SIZE,
            HuksParamValue.Uint32Value(HuksKeySize.HUKS_ECC_KEY_SIZE_256)
        ))
        // Harmony HUKS rejects combined purposes ("gen key purpose not unique",
        // purpose=260 = SIGN|AGREE, ret=-115). Document device keys only need
        // ES256; session ECDH uses a separate AGREE key (EcdhP256).
        list.add(HuksParam(
            HuksTag.HUKS_TAG_PURPOSE,
            HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN)
        ))
        list.add(HuksParam(
            HuksTag.HUKS_TAG_DIGEST,
            HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SHA256)
        ))
        match (authLevel) {
            case Some(level) =>
                list.add(HuksParam(
                    HuksTag.HUKS_TAG_AUTH_STORAGE_LEVEL,
                    HuksParamValue.Uint32Value(level)
                ))
            case None => ()
        }
        if (neverExport) {
            list.add(HuksParam(
                HuksTag.HUKS_TAG_KEY_STORAGE_FLAG,
                HuksParamValue.Uint32Value(HuksKeyStorageType.HUKS_STORAGE_ONLY_USED_IN_HUKS)
            ))
        }
        return list.toArray()
    }

    private func authLookupOptions(authLevel: ?UInt32): HuksOptions {
        match (authLevel) {
            case Some(level) =>
                return HuksOptions(
                    properties: [
                        HuksParam(
                            HuksTag.HUKS_TAG_AUTH_STORAGE_LEVEL,
                            HuksParamValue.Uint32Value(level)
                        )
                    ],
                    inData: Array<UInt8>()
                )
            case None => return HuksOptions()
        }
    }

    private func tryDeleteHuksAlias(alias: String, authLevel: ?UInt32): Unit {
        try {
            deleteKeyItem(alias, this.authLookupOptions(authLevel))
        } catch (_: Exception) {
            ()
        }
    }

    /** True when the slot was generated as a HUKS agreement (ECDH-only) key. */
    private func isAgreementSlot(slot: HashMap<String, Array<UInt8>>, index: Int64): Bool {
        let purposeKey = storageKey("huksPurpose", index)
        if (!slot.contains(purposeKey)) {
            return false
        }
        return String.fromUtf8(slot[purposeKey]) == "agree"
    }

    private func decodeStoredAuthLevel(slot: HashMap<String, Array<UInt8>>, index: Int64): ?UInt32 {
        let authKey = storageKey("huksAuth", index)
        if (!slot.contains(authKey)) {
            return None
        }
        let label = String.fromUtf8(slot[authKey])
        if (label == "CE") {
            return Some(HuksAuthStorageLevel.HUKS_AUTH_STORAGE_LEVEL_CE)
        }
        if (label == "DE") {
            return Some(HuksAuthStorageLevel.HUKS_AUTH_STORAGE_LEVEL_DE)
        }
        return None
    }

    /**
     * Generate a HUKS P-256 sign key and export the public SPKI.
     * Prefers CE + never-export; falls back to DE + never-export; then
     * the original purpose-only properties if the device rejects those tags.
     * Returns (pubDer, authLabel) so later sign/delete use the same storage level.
     * Public export size is logged as a probe (P-256 SPKI is 91 bytes).
     */
    private func generateSignKeyAndExportPublic(alias: String): (Array<UInt8>, String) {
        try {
            let ce = Some(HuksAuthStorageLevel.HUKS_AUTH_STORAGE_LEVEL_CE)
            generateKeyItem(
                alias,
                HuksOptions(
                    properties: this.signGenerateProperties(ce, true),
                    inData: Array<UInt8>()
                )
            )
            let pubDer = exportKeyItem(alias, this.authLookupOptions(ce))
            Hilog.info(0, "SecureArea", "HuksSecureArea.generate alias=" + alias
                + " auth=CE neverExport=1 pubDerLen=" + pubDer.size.toString())
            return (pubDer, "CE")
        } catch (eCe: Exception) {
            this.tryDeleteHuksAlias(alias, Some(HuksAuthStorageLevel.HUKS_AUTH_STORAGE_LEVEL_CE))
            Hilog.info(0, "SecureArea", "HuksSecureArea.generate CE failed alias=" + alias
                + " " + eCe.message)
        }
        try {
            let de = Some(HuksAuthStorageLevel.HUKS_AUTH_STORAGE_LEVEL_DE)
            generateKeyItem(
                alias,
                HuksOptions(
                    properties: this.signGenerateProperties(de, true),
                    inData: Array<UInt8>()
                )
            )
            let pubDer = exportKeyItem(alias, this.authLookupOptions(de))
            Hilog.info(0, "SecureArea", "HuksSecureArea.generate alias=" + alias
                + " auth=DE neverExport=1 pubDerLen=" + pubDer.size.toString())
            return (pubDer, "DE")
        } catch (eDe: Exception) {
            this.tryDeleteHuksAlias(alias, Some(HuksAuthStorageLevel.HUKS_AUTH_STORAGE_LEVEL_DE))
            Hilog.info(0, "SecureArea", "HuksSecureArea.generate DE failed alias=" + alias
                + " " + eDe.message)
        }
        generateKeyItem(
            alias,
            HuksOptions(
                properties: this.signGenerateProperties(None, false),
                inData: Array<UInt8>()
            )
        )
        let pubDer = exportKeyItem(alias, HuksOptions())
        Hilog.info(0, "SecureArea", "HuksSecureArea.generate alias=" + alias
            + " auth=default neverExport=0 pubDerLen=" + pubDer.size.toString())
        return (pubDer, "default")
    }

    /**
     * Create a batch of HUKS-resident P-256 key pairs.
     *
     * For each slot i in [0, batchSize):
     *   1. Generates a HUKS ECC P-256 key under alias huksAlias(id, i).
     *   2. Exports the public key (DER X.509 SubjectPublicKeyInfo) via exportKeyItem.
     *   3. Converts to x963 (65B) and stores in SecureKeyStorage under "pubX963_<i>".
     *   4. Stores the alias bytes under "huksAlias_<i>" for retrieval during sign/agree.
     *
     * Stores KeyBatchInfo CBOR under "<id>_meta" slot.
     */
    public func createKeyBatch(
        id: String,
        credentialOptions: CredentialOptions,
        keyOptions: ?KeyOptions
    ): KeyBatchInfo {
        let curve = match (keyOptions) {
            case Some(ko) => ko.curve
            case None => CoseEcCurve.P256
        }
        if (!isP256(curve)) {
            throw SecureAreaError("HuksSecureArea: unsupported curve " + curve.jwkName())
        }
        let batchSize = credentialOptions.batchSize
        let usedCounts = Array<Int64>(batchSize, {_ => Int64(0)})
        // Purpose-driven generation: an agreement-only batch (ISO 18013-5
        // ephemeral EDeviceKey) is a HUKS_KEY_PURPOSE_AGREE key so that
        // keyAgreement() can run ECDH on it; everything else is a sign key.
        let agreeOnly = match (keyOptions) {
            case Some(ko) => isAgreementOnly(ko.keyPurposes)
            case None => false
        }
        var i: Int64 = 0
        while (i < batchSize) {
            let alias = this.huksAlias(id, i)
            let pubDer: Array<UInt8>
            let authLabel: String
            try {
                if (agreeOnly) {
                    EcdhP256.generateKey(alias)
                    pubDer = EcdhP256.exportPublicKey(alias)
                    authLabel = "default"
                    Hilog.info(0, "SecureArea", "HuksSecureArea.generate alias=" + alias
                        + " purpose=agree pubDerLen=" + pubDer.size.toString())
                } else {
                    let (generatedPub, generatedAuth) = this.generateSignKeyAndExportPublic(alias)
                    pubDer = generatedPub
                    authLabel = generatedAuth
                }
            } catch (e: Exception) {
                throw SecureAreaError(
                    "HuksSecureArea.createKeyBatch: generateKeyItem failed alias=" +
                    alias + " " + e.message
                )
            }
            let pubX963 = extractX963FromDer(pubDer)
            let aliasBytes = alias.toArray()
            let slot = HashMap<String, Array<UInt8>>()
            slot[storageKey("huksAlias", i)] = aliasBytes
            slot[storageKey("pubX963", i)] = pubX963
            slot[storageKey("huksAuth", i)] = authLabel.toArray()
            if (agreeOnly) {
                slot[storageKey("huksPurpose", i)] = "agree".toArray()
            }
            this.storage.writeKeyInfo(storageKey(id, i), slot)
            i++
        }
        let purposes: Array<KeyPurpose> = if (agreeOnly) {
            [KeyPurpose.KeyAgreement]
        } else {
            KeyPurpose.allCases()
        }
        let kbi = KeyBatchInfo(
            Some(HuksSecureArea.NAME),
            CoseEcCurve.P256,
            usedCounts,
            credentialOptions.credentialPolicy,
            Some(purposes),
            None
        )
        let kbiSlot = HashMap<String, Array<UInt8>>()
        kbiSlot["kbiBytes"] = kbi.toBytes()
        this.storage.writeKeyInfo(id + "_meta", kbiSlot)
        Hilog.info(0, "SecureArea", "HuksSecureArea.createKeyBatch id=" + id
            + " batchSize=" + batchSize.toString())
        return kbi
    }

    /**
     * Return stored 65-byte x963 public key bytes for the key at index.
     */
    public func getPublicKeyBytes(id: String, index: Int64, curve: CoseEcCurve): Array<UInt8> {
        if (!isP256(curve)) {
            throw SecureAreaError("HuksSecureArea: unsupported curve " + curve.jwkName())
        }
        let slot = this.storage.readKeyInfo(storageKey(id, index))
        let slotKey = storageKey("pubX963", index)
        if (slot.contains(slotKey)) {
            return slot[slotKey]
        }
        throw SecureAreaError("HuksSecureArea.getPublicKeyBytes: no key for id=" + id
            + " index=" + index.toString())
    }

    /**
     * HUKS hardware keys need no explicit unlock; returns None.
     * Biometric prompts are handled by HUKS internally when required by key access control.
     */
    public func unlockKey(id: String): ?Array<UInt8> {
        return None
    }

    /**
     * Delete HUKS keys for the given batch slice.
     *
     * Loads each alias from SecureKeyStorage and calls deleteKeyItem on HUKS.
     */
    public func deleteKeyBatch(id: String, startIndex: Int64, batchSize: Int64): Unit {
        var i = startIndex
        while (i < startIndex + batchSize) {
            let slotId = storageKey(id, i)
            let aliasKey = storageKey("huksAlias", i)
            let slot = this.storage.readKeyInfo(slotId)
            if (slot.contains(aliasKey)) {
                let aliasBytes = slot[aliasKey]
                let alias = String.fromUtf8(aliasBytes)
                deleteKeyItem(alias, this.authLookupOptions(this.decodeStoredAuthLevel(slot, i)))
            }
            this.storage.deleteKeyBatch(slotId, 0, 1)
            i++
        }
    }

    /** Delete key metadata. */
    public func deleteKeyInfo(id: String): Unit {
        this.storage.deleteKeyInfo(id + "_meta")
    }

    /**
     * Compute an ES256 signature over dataToSign using the HUKS P-256 key at index.
     *
     * HUKS sign flow (ECDSA-SHA256):
     *   1. initSession with HUKS_KEY_PURPOSE_SIGN + HUKS_DIGEST_SHA256
     *   2. finishSession with dataToSign as inData
     *
     * Returns raw r||s (64 bytes) after converting from HUKS DER output via EcdsaP256.derToRaw().
     *
     * Only SigningAlgorithm.ES256 is supported.
     */
    public func signature(
        id: String,
        index: Int64,
        algorithm: SigningAlgorithm,
        dataToSign: Array<UInt8>,
        unlockData: ?Array<UInt8>
    ): Array<UInt8> {
        if (!isES256(algorithm)) {
            throw SecureAreaError(
                "HuksSecureArea: unsupported algorithm"
            )
        }
        let slot = this.storage.readKeyInfo(storageKey(id, index))
        let aliasKey = storageKey("huksAlias", index)
        if (!slot.contains(aliasKey)) {
            throw SecureAreaError(
                "HuksSecureArea.signature: no HUKS alias for id=" + id
                + " index=" + index.toString()
            )
        }
        if (this.isAgreementSlot(slot, index)) {
            throw SecureAreaError(
                "HuksSecureArea.signature: key id=" + id + " index=" + index.toString()
                + " is a key-agreement key and cannot sign"
            )
        }
        let alias = String.fromUtf8(slot[aliasKey])
        let signList = ArrayList<HuksParam>()
        signList.add(HuksParam(
            HuksTag.HUKS_TAG_ALGORITHM,
            HuksParamValue.Uint32Value(HuksKeyAlg.HUKS_ALG_ECC)
        ))
        signList.add(HuksParam(
            HuksTag.HUKS_TAG_KEY_SIZE,
            HuksParamValue.Uint32Value(HuksKeySize.HUKS_ECC_KEY_SIZE_256)
        ))
        signList.add(HuksParam(
            HuksTag.HUKS_TAG_PURPOSE,
            HuksParamValue.Uint32Value(HuksKeyPurpose.HUKS_KEY_PURPOSE_SIGN)
        ))
        signList.add(HuksParam(
            HuksTag.HUKS_TAG_DIGEST,
            HuksParamValue.Uint32Value(HuksKeyDigest.HUKS_DIGEST_SHA256)
        ))
        match (this.decodeStoredAuthLevel(slot, index)) {
            case Some(level) =>
                signList.add(HuksParam(
                    HuksTag.HUKS_TAG_AUTH_STORAGE_LEVEL,
                    HuksParamValue.Uint32Value(level)
                ))
            case None => ()
        }
        let signProperties = signList.toArray()
        let session = initSession(alias,
            HuksOptions(properties: signProperties, inData: Array<UInt8>()))
        let finishResult = finishSession(session.handle,
            HuksOptions(properties: signProperties, inData: dataToSign))
        let derSig: Array<UInt8> = match (finishResult) {
            case Some(bytes) => bytes
            case None =>
                throw SecureAreaError(
                    "HuksSecureArea.signature: HUKS finishSession returned no data"
                )
        }
        let rawSig = EcdsaP256.derToRaw(derSig)
        Hilog.info(0, "SecureArea", "HuksSecureArea.signature id=" + id
            + " index=" + index.toString())
        return rawSig
    }

    /**
     * Compute ECDH P-256 shared secret using the HUKS key at index and the remote public key.
     *
     * Delegates to EcdhP256.agree() from core-crypto, using the HUKS alias for this slot.
     * The publicKeyBytes must be the 65-byte uncompressed x963 point (0x04||X||Y).
     *
     * This is a device-only operation; HUKS must be available.
     */
    public func keyAgreement(
        id: String,
        index: Int64,
        publicKeyBytes: Array<UInt8>,
        unlockData: ?Array<UInt8>
    ): Array<UInt8> {
        let slot = this.storage.readKeyInfo(storageKey(id, index))
        let aliasKey = storageKey("huksAlias", index)
        if (!slot.contains(aliasKey)) {
            throw SecureAreaError(
                "HuksSecureArea.keyAgreement: no HUKS alias for id=" + id
                + " index=" + index.toString()
            )
        }
        let alias = String.fromUtf8(slot[aliasKey])
        let sharedSecret = EcdhP256.agree(alias, huksPeerPublicKeyDer(publicKeyBytes))
        Hilog.info(0, "SecureArea", "HuksSecureArea.keyAgreement id=" + id
            + " index=" + index.toString())
        return sharedSecret
    }

    /** Retrieve key batch metadata from storage. */
    public func getKeyBatchInfo(id: String): KeyBatchInfo {
        let metaSlot = this.storage.readKeyInfo(id + "_meta")
        if (!metaSlot.contains("kbiBytes")) {
            throw SecureAreaError(
                "HuksSecureArea.getKeyBatchInfo: no metadata for id=" + id
            )
        }
        return KeyBatchInfo.fromBytes(metaSlot["kbiBytes"])
    }

    /** Default signing algorithm for the given curve. */
    public func defaultSigningAlgorithm(ecCurve: CoseEcCurve): SigningAlgorithm {
        return ecCurve.defaultSigningAlgorithm()
    }
}
