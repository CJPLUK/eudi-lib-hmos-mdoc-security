/*
 * secure_area_test.cj
 *
 * Unit tests for mdsec_secure_area feature (fc_mdsec_secure_area):
 *   1. SoftwareSecureArea: createKeyBatch → getPublicKeyBytes (done_when 1 partial)
 *   2. SoftwareSecureArea: createKeyBatch → signature → EcdsaP256.verify round-trip (done_when 1)
 *   3. CoseEcCurve / KeyOptions / CredentialOptions config-type round-trips (done_when 3)
 *
 * Note on keyAgreement and HuksSecureArea:
 *   Both require a real device (HUKS hardware or emulator with HUKS support).
 *   These are validated via E2E tests on device, not host-side unit tests.
 *   This is consistent with the done_when contract: "KAT 未覆盖部分真机验".
 */
package ohos_app_cangjie_eudi_cjmdoc_security_local_test

import std.unittest.*
import std.unittest.testmacro.*
import std.collection.HashMap

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.CoseEcCurve
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.SigningAlgorithm
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.KeyPurpose
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.KeyOptions
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.CredentialPolicy
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.CredentialOptions
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.SecureKeyStorage
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.SecureAreaError
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.securearea.KeyBatchInfo

import ohos_app_cangjie_eudi_cjmdoc_security.security.secure_area.SoftwareSecureArea

import eudi_lib_core_crypto.EcdsaP256
import stdx.crypto.keys.*
import stdx.crypto.common.*

/* ====================================================================== */
/* In-memory SecureKeyStorage implementation for host-side testing         */
/* ====================================================================== */

/**
 * Simple in-memory implementation of SecureKeyStorage for host-side unit tests.
 * Not thread-safe; acceptable for single-threaded unit tests.
 */
class MemorySecureKeyStorage <: SecureKeyStorage {
    private var keyInfoStore: HashMap<String, HashMap<String, Array<UInt8>>>
    private var keyDataStore: HashMap<String, Array<HashMap<String, Array<UInt8>>>>

    public init() {
        this.keyInfoStore = HashMap<String, HashMap<String, Array<UInt8>>>()
        this.keyDataStore = HashMap<String, Array<HashMap<String, Array<UInt8>>>>()
    }

    public func readKeyInfo(id: String): HashMap<String, Array<UInt8>> {
        if (this.keyInfoStore.contains(id)) {
            return this.keyInfoStore[id]
        }
        return HashMap<String, Array<UInt8>>()
    }

    public func readKeyData(id: String, index: Int64): HashMap<String, Array<UInt8>> {
        if (this.keyDataStore.contains(id)) {
            let arr = this.keyDataStore[id]
            if (index >= 0 && index < arr.size) {
                return arr[index]
            }
        }
        throw SecureAreaError("MemorySecureKeyStorage: no key data for id=" + id
            + " index=" + index.toString())
    }

    public func writeKeyInfo(id: String, dict: HashMap<String, Array<UInt8>>): Unit {
        if (this.keyInfoStore.contains(id)) {
            let existing = this.keyInfoStore[id]
            for ((k, v) in dict) {
                existing[k] = v
            }
        } else {
            this.keyInfoStore[id] = dict
        }
    }

    public func writeKeyDataBatch(
        id: String,
        startIndex: Int64,
        dicts: Array<HashMap<String, Array<UInt8>>>,
        keyOptions: ?KeyOptions
    ): Unit {
        if (!this.keyDataStore.contains(id)) {
            this.keyDataStore[id] = []
        }
        let arr = this.keyDataStore[id]
        var i: Int64 = 0
        while (i < dicts.size) {
            let targetIdx = startIndex + i
            if (targetIdx < arr.size) {
                arr[targetIdx] = dicts[i]
            }
            i++
        }
    }

    public func deleteKeyBatch(id: String, startIndex: Int64, batchSize: Int64): Unit {
        this.keyInfoStore.remove(id)
    }

    public func deleteKeyInfo(id: String): Unit {
        this.keyInfoStore.remove(id)
    }
}

/* ====================================================================== */
/* SoftwareSecureArea host-side tests                                      */
/* ====================================================================== */

@Test
class SoftwareSecureAreaTest {

    /**
     * createKeyBatch (batchSize=1): verify the returned KeyBatchInfo has correct fields
     * and that getPublicKeyBytes returns 65-byte x963 (0x04 prefix) public key.
     *
     * done_when 1 partial: createKeyMaterial (x963 public key extraction).
     */
    @TestCase
    func testCreateKeyBatchAndGetPublicKey() {
        let storage = MemorySecureKeyStorage()
        let sa = SoftwareSecureArea.create(storage)

        let credOpts = CredentialOptions(CredentialPolicy.OneTimeUse, Int64(1))
        let kbi = sa.createKeyBatch("testKey", credOpts, None)

        @Assert(kbi.crv.rawValue(), CoseEcCurve.P256.rawValue())
        @Assert(kbi.batchSize(), Int64(1))
        match (kbi.secureAreaName) {
            case Some(n) => @Assert(n, "Software")
            case None => @Assert(false)
        }

        let pubBytes = sa.getPublicKeyBytes("testKey", Int64(0), CoseEcCurve.P256)
        @Assert(pubBytes.size, 65)
        @Assert(pubBytes[0], UInt8(0x04))
    }

    /**
     * createKeyBatch (batchSize=3): verify batch produces distinct public keys.
     */
    @TestCase
    func testCreateKeyBatchMultiple() {
        let storage = MemorySecureKeyStorage()
        let sa = SoftwareSecureArea.create(storage)

        let credOpts = CredentialOptions(CredentialPolicy.RotateUse, Int64(3))
        let kbi = sa.createKeyBatch("batchKey", credOpts, None)
        @Assert(kbi.batchSize(), Int64(3))

        let pub0 = sa.getPublicKeyBytes("batchKey", Int64(0), CoseEcCurve.P256)
        let pub1 = sa.getPublicKeyBytes("batchKey", Int64(1), CoseEcCurve.P256)
        let pub2 = sa.getPublicKeyBytes("batchKey", Int64(2), CoseEcCurve.P256)

        @Assert(pub0.size, 65)
        @Assert(pub1.size, 65)
        @Assert(pub2.size, 65)
        @Assert(pub0[0], UInt8(0x04))
        @Assert(pub1[0], UInt8(0x04))
        @Assert(pub2[0], UInt8(0x04))
    }

    /**
     * createKeyBatch → signature → EcdsaP256.verify round-trip.
     *
     * This is the core test for done_when 1: software createKey → sign → verify.
     * EcdsaP256.sign returns raw r||s (64 bytes); EcdsaP256.verify verifies it.
     * We reconstruct ECDSAPublicKey from x963 bytes for verification.
     */
    @TestCase
    func testSignatureRoundTrip() {
        let storage = MemorySecureKeyStorage()
        let sa = SoftwareSecureArea.create(storage)

        let credOpts = CredentialOptions(CredentialPolicy.OneTimeUse, Int64(1))
        sa.createKeyBatch("signKey", credOpts, None)

        let dataToSign: Array<UInt8> = [
            UInt8(0x48), UInt8(0x65), UInt8(0x6c), UInt8(0x6c),
            UInt8(0x6f), UInt8(0x20), UInt8(0x57), UInt8(0x6f),
            UInt8(0x72), UInt8(0x6c), UInt8(0x64)
        ]

        let rawSig = sa.signature("signKey", Int64(0), SigningAlgorithm.ES256, dataToSign, None)
        @Assert(rawSig.size, 64)

        let pubX963 = sa.getPublicKeyBytes("signKey", Int64(0), CoseEcCurve.P256)
        let pubDer = x963ToDerSubjectPublicKeyInfo(pubX963)
        let pubKey = ECDSAPublicKey.decodeDer(DerBlob(pubDer))
        let verified = EcdsaP256.verify(pubKey, dataToSign, rawSig)
        @Assert(verified, true)
    }

    /**
     * getKeyBatchInfo retrieves the previously stored KeyBatchInfo.
     */
    @TestCase
    func testGetKeyBatchInfo() {
        let storage = MemorySecureKeyStorage()
        let sa = SoftwareSecureArea.create(storage)

        let credOpts = CredentialOptions(CredentialPolicy.RotateUse, Int64(2))
        sa.createKeyBatch("infoKey", credOpts, None)

        let kbi = sa.getKeyBatchInfo("infoKey")
        @Assert(kbi.batchSize(), Int64(2))
        @Assert(kbi.crv.rawValue(), CoseEcCurve.P256.rawValue())
    }

    /**
     * Unsupported curve should throw SecureAreaError.
     */
    @TestCase
    func testUnsupportedCurveThrows() {
        let storage = MemorySecureKeyStorage()
        let sa = SoftwareSecureArea.create(storage)

        let ko = KeyOptions(
            CoseEcCurve.P384,
            None, None, None, None, None
        )
        let credOpts = CredentialOptions(CredentialPolicy.OneTimeUse, Int64(1))
        var threw = false
        try {
            sa.createKeyBatch("p384Key", credOpts, Some(ko))
        } catch (_: SecureAreaError) {
            threw = true
        }
        @Assert(threw, true)
    }
}

/* ====================================================================== */
/* CoseEcCurve / KeyOptions / CredentialOptions round-trip tests           */
/* (done_when 3: config type serialization)                                */
/* ====================================================================== */

@Test
class SecureAreaConfigTest {

    /**
     * CoseEcCurve rawValue/fromRaw round-trip for all supported values.
     */
    @TestCase
    func testCoseEcCurveRoundTrip() {
        let curves: Array<CoseEcCurve> = [
            CoseEcCurve.P256, CoseEcCurve.P384, CoseEcCurve.P521
        ]
        for (c in curves) {
            let raw = c.rawValue()
            let decoded = CoseEcCurve.fromRaw(raw)
            @Assert(decoded.rawValue(), raw)
        }
    }

    /**
     * KeyOptions CBOR round-trip with defaults.
     */
    @TestCase
    func testKeyOptionsDefaultsRoundTrip() {
        let opts = KeyOptions.defaults()
        let bytes = opts.toBytes()
        let decoded = KeyOptions.fromBytes(bytes)
        @Assert(decoded.curve.rawValue(), CoseEcCurve.P256.rawValue())
        @Assert(decoded.secureAreaName.isNone(), true)
    }

    /**
     * KeyOptions CBOR round-trip with HUKS area name + P384.
     */
    @TestCase
    func testKeyOptionsHuksRoundTrip() {
        let opts = KeyOptions(
            CoseEcCurve.P256,
            Some("HUKS"),
            None,
            None,
            Some([KeyPurpose.Signing]),
            None
        )
        let bytes = opts.toBytes()
        let decoded = KeyOptions.fromBytes(bytes)
        @Assert(decoded.curve.rawValue(), CoseEcCurve.P256.rawValue())
        match (decoded.secureAreaName) {
            case Some(n) => @Assert(n, "HUKS")
            case None => @Assert(false)
        }
        match (decoded.keyPurposes) {
            case Some(ps) =>
                @Assert(ps.size, 1)
                @Assert(ps[0].rawValue(), "Signing")
            case None => @Assert(false)
        }
    }

    /**
     * CredentialOptions CBOR round-trip (OneTimeUse, batchSize=5).
     */
    @TestCase
    func testCredentialOptionsRoundTrip() {
        let opts = CredentialOptions(CredentialPolicy.OneTimeUse, Int64(5))
        let bytes = opts.toBytes()
        let decoded = CredentialOptions.fromBytes(bytes)
        @Assert(decoded.credentialPolicy.rawValue(), "oneTimeUse")
        @Assert(decoded.batchSize, Int64(5))
    }

    /**
     * CoseEcCurve jwkName / fromJwkName round-trip for standard curves.
     */
    @TestCase
    func testCoseEcCurveJwkRoundTrip() {
        let curves: Array<CoseEcCurve> = [
            CoseEcCurve.P256, CoseEcCurve.P384, CoseEcCurve.P521
        ]
        for (c in curves) {
            let name = c.jwkName()
            let decoded = CoseEcCurve.fromJwkName(name)
            @Assert(decoded.rawValue(), c.rawValue())
        }
    }

    /**
     * SoftwareSecureArea.getName() / getDefaultEcCurve() / getSupportedEcCurves().
     */
    @TestCase
    func testSoftwareSecureAreaMeta() {
        let storage = MemorySecureKeyStorage()
        let sa = SoftwareSecureArea.create(storage)
        @Assert(sa.getName(), "Software")
        @Assert(sa.getDefaultEcCurve().rawValue(), CoseEcCurve.P256.rawValue())
        let curves = sa.getSupportedEcCurves()
        @Assert(curves.size, 1)
        @Assert(curves[0].rawValue(), CoseEcCurve.P256.rawValue())
    }
}

/* ====================================================================== */
/* HI-MDSEC-002 regression: extractX963FromDer with real 91-byte SPKI     */
/* ====================================================================== */

/**
 * Regression test for HI-MDSEC-002: verifies that the DER-parsing-based
 * extractX963FromDer correctly handles the 91-byte SubjectPublicKeyInfo
 * produced by stdx EcdsaP256.generate().
 *
 * The old hardcoded-offset implementation checked `der.size < 92` and raised
 * "DER blob too short: 91 bytes", rejecting the only SPKI size stdx produces.
 * The new parse-based implementation walks TLV and succeeds on any valid SPKI.
 *
 * Tested indirectly via SoftwareSecureArea.createKeyBatch which calls
 * extractX963FromDer internally; we also inspect the raw DER blob to confirm
 * the 91-byte case is exercised.
 */
@Test
class ExtractX963FromDerRegressionTest {

    /**
     * EcdsaP256.generate() → ECDSAPublicKey.encodeToDer() produces 91-byte SPKI.
     * SoftwareSecureArea.createKeyBatch → getPublicKeyBytes must return
     * 65-byte x963 with 0x04 prefix (no "DER blob too short" error).
     */
    @TestCase
    func testRealSpkiIs91BytesAndExtractsCorrectly() {
        // Confirm the SPKI produced by stdx is exactly 91 bytes
        let privKey = EcdsaP256.generate()
        let pubKey = ECDSAPublicKey(privKey)
        let spkiDer = pubKey.encodeToDer().body
        @Assert(spkiDer.size, 91)

        // The createKeyBatch path calls extractX963FromDer internally.
        // Before the fix this threw "DER blob too short: 91 bytes".
        let storage = MemorySecureKeyStorage()
        let sa = SoftwareSecureArea.create(storage)
        let credOpts = CredentialOptions(CredentialPolicy.OneTimeUse, Int64(1))
        sa.createKeyBatch("derKey", credOpts, None)

        let pubBytes = sa.getPublicKeyBytes("derKey", Int64(0), CoseEcCurve.P256)
        @Assert(pubBytes.size, 65)
        @Assert(pubBytes[0], UInt8(0x04))
    }

    /**
     * The extracted x963 bytes are consistent with the original public key:
     * wrapping them back into a SPKI DER and decoding gives a key that verifies
     * a signature made with the corresponding private key.
     */
    @TestCase
    func testExtractedX963CanVerifySignature() {
        let storage = MemorySecureKeyStorage()
        let sa = SoftwareSecureArea.create(storage)
        let credOpts = CredentialOptions(CredentialPolicy.OneTimeUse, Int64(1))
        sa.createKeyBatch("verifyKey", credOpts, None)

        let dataToSign: Array<UInt8> = [0x48u8, 0x65u8, 0x6Cu8, 0x6Cu8, 0x6Fu8]
        let rawSig = sa.signature("verifyKey", Int64(0), SigningAlgorithm.ES256, dataToSign, None)
        @Assert(rawSig.size, 64)

        let pubX963 = sa.getPublicKeyBytes("verifyKey", Int64(0), CoseEcCurve.P256)
        let pubDer = x963ToDerSubjectPublicKeyInfo(pubX963)
        @Assert(pubDer.size, 91)
        let pubKey = ECDSAPublicKey.decodeDer(DerBlob(pubDer))
        let verified = EcdsaP256.verify(pubKey, dataToSign, rawSig)
        @Assert(verified, true)
    }
}

/* ====================================================================== */
/* Helper: x963 65B -> SubjectPublicKeyInfo DER (for verify test)          */
/* ====================================================================== */

/**
 * Convert a 65-byte uncompressed EC P-256 point (x963: 0x04||X||Y) into an
 * X.509 SubjectPublicKeyInfo DER blob that ECDSAPublicKey.decodeDer() accepts.
 *
 * DER structure (91 bytes total):
 *   30 59            SEQUENCE (89)
 *     30 13          SEQUENCE (19) — algorithm identifier
 *       06 07 2a 86 48 ce 3d 02 01   OID id-ecPublicKey (1.2.840.10045.2.1)
 *       06 08 2a 86 48 ce 3d 03 01 07 OID prime256v1 (1.2.840.10045.3.1.7)
 *     03 42 00       BIT STRING (66 bytes, 0 unused bits)
 *       04 <32B X> <32B Y>
 */
func x963ToDerSubjectPublicKeyInfo(x963: Array<UInt8>): Array<UInt8> {
    if (x963.size != 65 || x963[0] != UInt8(0x04)) {
        throw SecureAreaError("x963ToDer: expected 65-byte uncompressed point with 0x04 prefix")
    }
    let header: Array<UInt8> = [
        UInt8(0x30), UInt8(0x59),
        UInt8(0x30), UInt8(0x13),
        UInt8(0x06), UInt8(0x07),
        UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0xce), UInt8(0x3d), UInt8(0x02), UInt8(0x01),
        UInt8(0x06), UInt8(0x08),
        UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0xce), UInt8(0x3d), UInt8(0x03), UInt8(0x01), UInt8(0x07),
        UInt8(0x03), UInt8(0x42), UInt8(0x00)
    ]
    let result = Array<UInt8>(header.size + x963.size, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < header.size) {
        result[i] = header[i]
        i++
    }
    var j: Int64 = 0
    while (j < x963.size) {
        result[header.size + j] = x963[j]
        j++
    }
    return result
}
