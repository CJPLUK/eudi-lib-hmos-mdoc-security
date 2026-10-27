/*
 * mso_validation.cj
 *
 * ISO 18013-5 §9.1.2 — MSO Issuer Authentication validation.
 *
 * Implements:
 *   done_when 1: validateDigestValues — MSO ValueDigests vs actual IssuerSignedItem digest
 *   done_when 2: validateValidityInfo + digestAlgorithm support check
 *   done_when 3: MSO issuer certificate chain via x509.verifyChain
 *
 * iOS references:
 *   Sources/MdocSecurity18013/IssuerAuthentication/MsoValidation.swift
 *   Sources/MdocSecurity18013/IssuerAuthentication/DigestCalculations.swift
 *   Sources/MdocSecurity18013/IssuerAuthentication/MsoValidationError.swift
 *
 * Design notes:
 *   - MsoValidationError is a class extending Exception (Cangjie enums cannot extend
 *     Exception — R-100). The error kind is represented by MsoValidationErrorKind enum.
 *   - digest computation: IssuerSignedItem.encode() returns rawData (the original Tag-24
 *     bstr bytes as received from the wire). This is the input to the hash, matching iOS
 *     signedItem.encode(options:).taggedEncoded.encode() which hashes the Tag-24 wrapper.
 *   - ValidityInfo timestamps are RFC 3339 strings; parsed with DateTime.parse(String).
 *   - verifyChain: leaf = x5chain[0], intermediates = x5chain[1..], roots = caller-supplied.
 */
package ohos_app_cangjie_eudi_cjmdoc_security.security.issuer_auth

import std.collection.ArrayList
import std.time.DateTime

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.issuerauth.MobileSecurityObject
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.issuerauth.IssuerAuth
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.issuerauth.DigestAlgorithmKind
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.issuerauth.ValueDigests
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.response.IssuerSignedItem
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.response.IssuerNameSpaces

import ohos_app_cangjie_eudi_cjcbor.cbor.CborValue
import ohos_app_cangjie_eudi_cjcbor.cbor.CborTag

import eudi_lib_core_crypto.Digest

import ohos_app_cangjie_eudi_cjx509.x509.core.Cert
import ohos_app_cangjie_eudi_cjx509.x509.core.CertError
import ohos_app_cangjie_eudi_cjx509.x509.core.verifyChain

import stdx.crypto.keys.ECDSAPublicKey
import stdx.crypto.common.DerBlob
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.core.CoseSign1
import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.engagement.CoseKey
import ohos_app_cangjie_eudi_cjmdoc_security.security.device_auth.MdocAuthentication

/* ===================================================================== */
/* MsoValidationErrorKind — typed error variants                         */
/* ===================================================================== */

/**
 * Error kind enum for MsoValidationError.
 * Cangjie enums cannot extend Exception (R-100), so the kind is a plain enum
 * and wrapped by MsoValidationError (class extending Exception).
 */
public enum MsoValidationErrorKind {
    /** docType in MSO does not match the expected docType. */
    | DocTypeNotMatches(String)
    /** digestAlgorithm string is not SHA-256, SHA-384, or SHA-512. */
    | UnsupportedDigestAlgorithm(String)
    /** One or more digest entries missing in ValueDigests for a namespace. */
    | MissingDigestValues(String, ArrayList<String>)
    /** One or more digest values in ValueDigests do not match computed digests. */
    | InvalidDigestValues(String, ArrayList<String>)
    /** MSO signature or certificate chain verification failed. */
    | SignatureVerificationFailed(String)
    /** ValidityInfo timestamp check failed. */
    | ValidityInfoError(String)
    /** Issuer trust (certificate chain) check failed. */
    | IssuerTrustFailed(String)
    /** Multiple errors collected during validation. */
    | MultipleErrors(ArrayList<MsoValidationError>)
}

/* ===================================================================== */
/* MsoValidationError — Exception wrapping MsoValidationErrorKind        */
/* ===================================================================== */

/**
 * Exception thrown (or collected) during MSO validation.
 * Mirrors iOS MsoValidationError enum, but implemented as class (R-100).
 */
public class MsoValidationError <: Exception {
    public let kind: MsoValidationErrorKind

    public init(k: MsoValidationErrorKind) {
        super(MsoValidationError.describe(k))
        this.kind = k
    }

    static func describe(k: MsoValidationErrorKind): String {
        match (k) {
            case MsoValidationErrorKind.DocTypeNotMatches(dt) =>
                return "The document type does not match the expected value '" + dt + "'"
            case MsoValidationErrorKind.UnsupportedDigestAlgorithm(alg) =>
                return "The digest algorithm " + alg + " is not supported"
            case MsoValidationErrorKind.MissingDigestValues(ns, elems) =>
                var s = "Digest values missing for namespace '" + ns + "' elements: "
                var first = true
                for (e in elems) {
                    if (!first) { s = s + ", " }
                    s = s + e
                    first = false
                }
                return s
            case MsoValidationErrorKind.InvalidDigestValues(ns, elems) =>
                var s = "Invalid digest values for namespace '" + ns + "' elements: "
                var first = true
                for (e in elems) {
                    if (!first) { s = s + ", " }
                    s = s + e
                    first = false
                }
                return s
            case MsoValidationErrorKind.SignatureVerificationFailed(reason) =>
                return "MSO signature verification failed: " + reason
            case MsoValidationErrorKind.ValidityInfoError(reason) =>
                return "MSO validity info check failed: " + reason
            case MsoValidationErrorKind.IssuerTrustFailed(reason) =>
                return "MSO issuer trust check failed: " + reason
            case MsoValidationErrorKind.MultipleErrors(errors) =>
                var s = "Multiple MSO validation errors: "
                var first = true
                for (e in errors) {
                    if (!first) { s = s + "; " }
                    s = s + e.message
                    first = false
                }
                return s
        }
    }

    /* Convenience factory methods */
    public static func docTypeNotMatches(dt: String): MsoValidationError {
        return MsoValidationError(MsoValidationErrorKind.DocTypeNotMatches(dt))
    }
    public static func unsupportedDigestAlgorithm(alg: String): MsoValidationError {
        return MsoValidationError(MsoValidationErrorKind.UnsupportedDigestAlgorithm(alg))
    }
    public static func missingDigestValues(ns: String, elems: ArrayList<String>): MsoValidationError {
        return MsoValidationError(MsoValidationErrorKind.MissingDigestValues(ns, elems))
    }
    public static func invalidDigestValues(ns: String, elems: ArrayList<String>): MsoValidationError {
        return MsoValidationError(MsoValidationErrorKind.InvalidDigestValues(ns, elems))
    }
    public static func signatureVerificationFailed(reason: String): MsoValidationError {
        return MsoValidationError(MsoValidationErrorKind.SignatureVerificationFailed(reason))
    }
    public static func validityInfoError(reason: String): MsoValidationError {
        return MsoValidationError(MsoValidationErrorKind.ValidityInfoError(reason))
    }
    public static func issuerTrustFailed(reason: String): MsoValidationError {
        return MsoValidationError(MsoValidationErrorKind.IssuerTrustFailed(reason))
    }
    public static func multipleErrors(errors: ArrayList<MsoValidationError>): MsoValidationError {
        return MsoValidationError(MsoValidationErrorKind.MultipleErrors(errors))
    }
}

/* ===================================================================== */
/* DigestCalculations — digest computation helper                        */
/* ===================================================================== */

/**
 * Computes digests for IssuerSignedItem objects.
 *
 * The digest is computed over IssuerSignedItem.encode(), which returns the
 * raw Tag-24-wrapped bytes (rawData) when the item was decoded from wire.
 * This matches ISO 18013-5 §9.1.2 and the iOS reference:
 *   signedItem.encode(options:).taggedEncoded.encode()  → same bytes
 *
 * iOS ref: DigestCalculations.swift
 */
public class DigestCalculations {

    /**
     * Compute the digest of a single IssuerSignedItem using the given algorithm.
     * Returns the raw digest bytes.
     */
    public static func computeDigest(item: IssuerSignedItem, algorithm: DigestAlgorithmKind): Array<UInt8> {
        // ISO 18013-5: the ValueDigests digest is computed over
        // IssuerSignedItemBytes = #6.24(bstr .cbor IssuerSignedItem) — the
        // Tag-24-WRAPPED encoding — mirroring iOS
        // signedItem.encode().taggedEncoded.encode() (DigestCalculations.swift).
        // item.encode() yields the inner bstr content (preserved rawData); it
        // MUST be re-wrapped in Tag-24 before hashing, otherwise every digest
        // mismatches the issuer's (previously validation only passed on
        // synthetic data that skipped the wrapper).
        let inner = item.encode()
        let itemBytes = CborValue.TaggedVal(CborTag.ENCODED_CBOR, CborValue.ByteStringVal(inner)).encode()
        match (algorithm) {
            case DigestAlgorithmKind.Sha256 => return Digest.sha256(itemBytes)
            case DigestAlgorithmKind.Sha384 => return Digest.sha384(itemBytes)
            case DigestAlgorithmKind.Sha512 => return Digest.sha512(itemBytes)
        }
    }

    /**
     * Compare two byte arrays for equality.
     */
    public static func bytesEqual(a: Array<UInt8>, b: Array<UInt8>): Bool {
        if (a.size != b.size) {
            return false
        }
        var i: Int64 = 0
        while (i < a.size) {
            if (a[i] != b[i]) {
                return false
            }
            i++
        }
        return true
    }

    /**
     * Validate digests for all items in a namespace.
     * Returns (missing: ArrayList<String>, failed: ArrayList<String>).
     */
    public static func validateDigestsForNamespace(
        ns: String,
        items: ArrayList<IssuerSignedItem>,
        algorithm: DigestAlgorithmKind,
        valueDigests: ValueDigests
    ): (ArrayList<String>, ArrayList<String>) {
        let missing = ArrayList<String>()
        let failed = ArrayList<String>()

        let nsDigestsOpt = valueDigests.get(ns)
        match (nsDigestsOpt) {
            case None =>
                for (item in items) {
                    missing.add(item.elementIdentifier)
                }
                return (missing, failed)
            case Some(nsDigestIDs) =>
                for (item in items) {
                    let digestOpt = nsDigestIDs.get(item.digestID)
                    match (digestOpt) {
                        case None =>
                            missing.add(item.elementIdentifier)
                        case Some(expectedDigest) =>
                            let computed = DigestCalculations.computeDigest(item, algorithm)
                            if (!DigestCalculations.bytesEqual(computed, expectedDigest)) {
                                failed.add(item.elementIdentifier)
                            }
                    }
                }
                return (missing, failed)
        }
    }
}

/* ===================================================================== */
/* MsoValidation — main MSO validation pipeline                          */
/* ===================================================================== */

/**
 * MSO validation pipeline.
 *
 * Validates the IssuerAuth MSO per ISO 18013-5 §9.1.2:
 *   1. digestAlgorithm support check (SHA-256/384/512)
 *   2. ValueDigests vs actual IssuerSignedItem digests (done_when 1)
 *   3. ValidityInfo timestamp checks (done_when 2)
 *   4. Issuer certificate chain via x509.verifyChain (done_when 3)
 *
 * iOS ref: MsoValidation.swift (IssuerSigned.validate)
 */
public class MsoValidation {

    /**
     * Validate MSO digest algorithm — must be SHA-256, SHA-384, or SHA-512.
     * Returns None if supported, MsoValidationError if not.
     */
    public static func validateDigestAlgorithm(mso: MobileSecurityObject): ?MsoValidationError {
        let algOpt = DigestAlgorithmKind.fromString(mso.digestAlgorithm)
        match (algOpt) {
            case Some(_) => return None
            case None => return Some(MsoValidationError.unsupportedDigestAlgorithm(mso.digestAlgorithm))
        }
    }

    /**
     * Validate that the MSO docType matches the expected docType.
     * Returns None if match, MsoValidationError otherwise.
     */
    public static func validateDocType(mso: MobileSecurityObject, expectedDocType: String): ?MsoValidationError {
        if (mso.docType == expectedDocType) {
            return None
        }
        return Some(MsoValidationError.docTypeNotMatches(mso.docType))
    }

    /**
     * Validate ValueDigests against actual IssuerSignedItem digests (done_when 1).
     *
     * For each namespace in issuerNameSpaces:
     *   - Looks up the corresponding DigestIDs in mso.valueDigests
     *   - For each IssuerSignedItem, computes digest over item.encode() bytes
     *   - Compares with the stored digest; collects missing/failed element IDs
     *
     * Returns list of MsoValidationError (one per problematic namespace), empty if all pass.
     *
     * iOS ref: validateDigestValues / validateDigests in DigestCalculations.swift
     */
    public static func validateDigestValues(
        mso: MobileSecurityObject,
        issuerNameSpaces: IssuerNameSpaces
    ): ArrayList<MsoValidationError> {
        let errors = ArrayList<MsoValidationError>()

        let algOpt = DigestAlgorithmKind.fromString(mso.digestAlgorithm)
        match (algOpt) {
            case None =>
                errors.add(MsoValidationError.unsupportedDigestAlgorithm(mso.digestAlgorithm))
                return errors
            case Some(algorithm) =>
                for ((ns, items) in issuerNameSpaces.nameSpaces) {
                    let (missing, failed) = DigestCalculations.validateDigestsForNamespace(
                        ns, items, algorithm, mso.valueDigests
                    )
                    if (missing.size > 0) {
                        errors.add(MsoValidationError.missingDigestValues(ns, missing))
                    }
                    if (failed.size > 0) {
                        errors.add(MsoValidationError.invalidDigestValues(ns, failed))
                    }
                }
                return errors
        }
    }

    /**
     * Validate ValidityInfo timestamps (done_when 2).
     *
     * Checks per iOS MsoValidation.swift validateValidityInfo:
     *   - signed date within DS certificate validity period
     *   - validFrom <= now + 60s (current time is not earlier than validFrom)
     *   - validFrom < validUntil (ordering)
     *   - validUntil + 60s >= now (document not expired)
     *
     * The 60-second tolerance mirrors iOS .addingTimeInterval(60) for clock skew.
     * DS cert is issuerAuth.x5chain[0].
     *
     * Returns list of MsoValidationError, empty if all pass.
     */
    public static func validateValidityInfo(
        mso: MobileSecurityObject,
        issuerAuth: IssuerAuth,
        rejectIfValidUntilExceedsCertValidity: Bool
    ): ArrayList<MsoValidationError> {
        let errors = ArrayList<MsoValidationError>()

        if (issuerAuth.x5chain.size == 0) {
            errors.add(MsoValidationError.signatureVerificationFailed("No issuer certificates provided in x5chain"))
            return errors
        }

        let dsCert: Cert
        try {
            dsCert = Cert.fromDer(issuerAuth.x5chain[0])
        } catch (_: CertError) {
            errors.add(MsoValidationError.signatureVerificationFailed("Failed to parse DS certificate from x5chain[0]"))
            return errors
        }

        let signedDt: DateTime
        let validFromDt: DateTime
        let validUntilDt: DateTime

        try {
            signedDt = DateTime.parse(mso.validityInfo.signed)
        } catch (_: Exception) {
            errors.add(MsoValidationError.validityInfoError("Cannot parse 'signed' date: " + mso.validityInfo.signed))
            return errors
        }
        try {
            validFromDt = DateTime.parse(mso.validityInfo.validFrom)
        } catch (_: Exception) {
            errors.add(MsoValidationError.validityInfoError("Cannot parse 'validFrom' date: " + mso.validityInfo.validFrom))
            return errors
        }
        try {
            validUntilDt = DateTime.parse(mso.validityInfo.validUntil)
        } catch (_: Exception) {
            errors.add(MsoValidationError.validityInfoError("Cannot parse 'validUntil' date: " + mso.validityInfo.validUntil))
            return errors
        }

        let certNotBefore = dsCert.notBefore
        let certNotAfter = dsCert.notAfter

        if (!(signedDt >= certNotBefore && signedDt <= certNotAfter)) {
            errors.add(MsoValidationError.validityInfoError(
                "The 'signed' date is not within the validity period of the certificate in the MSO: " +
                mso.validityInfo.signed + " (" + certNotBefore.toString() + " - " + certNotAfter.toString() + ")"
            ))
        }

        let now = DateTime.now()
        let skewSeconds: Int64 = 60
        let nowPlus60 = now.addSeconds(skewSeconds)

        if (!(validFromDt <= nowPlus60)) {
            errors.add(MsoValidationError.validityInfoError(
                "Current timestamp is not equal or later than the 'validFrom' element: " + mso.validityInfo.validFrom
            ))
        }

        if (!(validFromDt < validUntilDt)) {
            errors.add(MsoValidationError.validityInfoError(
                "The 'validFrom' element must be strictly earlier than the 'validUntil' element"
            ))
        }

        let validUntilPlus60 = validUntilDt.addSeconds(skewSeconds)
        if (!(validUntilPlus60 >= now)) {
            errors.add(MsoValidationError.validityInfoError(
                "Current timestamp is not less than the 'validUntil' element: " + mso.validityInfo.validUntil
            ))
        }

        if (rejectIfValidUntilExceedsCertValidity && validUntilDt > certNotAfter) {
            errors.add(MsoValidationError.validityInfoError(
                "The 'validUntil' element exceeds certificate validity"
            ))
        }

        return errors
    }

    /**
     * Validate the MSO issuer certificate chain (done_when 3).
     *
     * Constructs the chain from IssuerAuth.x5chain (DER bytes):
     *   leaf = x5chain[0]
     *   intermediates = x5chain[1..n-1]
     *   roots = trustedRoots parameter (caller provides)
     *
     * Uses ohos_app_cangjie_eudi_cjx509.x509.core.verifyChain.
     * Returns None if valid, MsoValidationError otherwise.
     *
     * iOS ref: validateMsoSignature — calls X509.Certificate chain verification.
     */
    public static func validateIssuerCertChain(
        issuerAuth: IssuerAuth,
        trustedRoots: ArrayList<Cert>
    ): ?MsoValidationError {
        if (issuerAuth.x5chain.size == 0) {
            return Some(MsoValidationError.issuerTrustFailed("No issuer certificates in x5chain"))
        }

        let leaf: Cert
        try {
            leaf = Cert.fromDer(issuerAuth.x5chain[0])
        } catch (_: CertError) {
            return Some(MsoValidationError.issuerTrustFailed("Cannot parse leaf certificate from x5chain[0]"))
        }

        let intermediates = ArrayList<Cert>()
        var i: Int64 = 1
        while (i < issuerAuth.x5chain.size) {
            try {
                intermediates.add(Cert.fromDer(issuerAuth.x5chain[i]))
            } catch (_: CertError) {
                return Some(MsoValidationError.issuerTrustFailed(
                    "Cannot parse intermediate certificate at x5chain[" + i.toString() + "]"
                ))
            }
            i++
        }

        let rootsArr = Array<Cert>(trustedRoots.size) { idx => trustedRoots[idx] }
        let intermediatesArr = Array<Cert>(intermediates.size) { idx => intermediates[idx] }

        try {
            let isValid = verifyChain(leaf, intermediatesArr, rootsArr)
            if (!isValid) {
                return Some(MsoValidationError.issuerTrustFailed("Certificate chain verification failed"))
            }
        } catch (e: CertError) {
            return Some(MsoValidationError.issuerTrustFailed("Certificate chain error: " + e.message))
        }

        return None
    }

    /**
     * Verify the IssuerAuth COSE_Sign1 signature with the DS (Document Signer)
     * certificate public key from x5chain[0]. This is the cryptographic proof
     * that the MSO was actually signed by the issuer's DS key — distinct from,
     * and NOT implied by, certificate-chain-to-root trust (validateIssuerCertChain).
     * Without it a forged/tampered MSO bearing any chain-valid DS cert would pass.
     *
     * iOS ref: MsoValidation.validateMsoSignature (the cose.validateDetachedCoseSign1
     * half; device-key binding is a separate check).
     */
    public static func validateMsoSignature(issuerAuth: IssuerAuth): ?MsoValidationError {
        if (issuerAuth.x5chain.size == 0) {
            return Some(MsoValidationError.signatureVerificationFailed("No issuer certificate in x5chain"))
        }
        // DS public key from the leaf certificate SPKI (same format reader auth uses).
        let dsPubKey: ECDSAPublicKey
        try {
            let leaf = Cert.fromDer(issuerAuth.x5chain[0])
            dsPubKey = ECDSAPublicKey.decodeDer(DerBlob(leaf.publicKeyDer))
        } catch (e: Exception) {
            return Some(MsoValidationError.signatureVerificationFailed(
                "Cannot extract DS public key from x5chain[0]: " + e.message))
        }
        // Reconstruct the detached COSE_Sign1 (protected alg + signature); the
        // signed payload is the raw MSO bytes (msoRawData).
        let sign1 = CoseSign1.create(issuerAuth.verifyAlgorithm, None, None, issuerAuth.signature)
        let sigValid = MdocAuthentication.verifyDetachedCoseSign1(sign1, issuerAuth.msoRawData, dsPubKey)
        if (!sigValid) {
            return Some(MsoValidationError.signatureVerificationFailed(
                "IssuerAuth COSE_Sign1 signature does not verify against the DS certificate public key"))
        }
        return None
    }

    /**
     * Device-key binding: the deviceKey carried in the MSO (deviceKeyInfo) must
     * match one of the device public keys the holder actually controls. Without
     * it, a validly-signed MSO issued for a *different* device key would be
     * accepted (cross-holder replay). Keys are compared in uncompressed x9.63
     * form (0x04 || X || Y), matching iOS deviceKey.x963Representation.
     *
     * iOS ref: MsoValidation.validateMsoSignature (device-key binding half).
     */
    public static func validateDeviceKeyBinding(
        issuerAuth: IssuerAuth,
        expectedDeviceKeysX963: Array<Array<UInt8>>
    ): ?MsoValidationError {
        let msoKeyX963: Array<UInt8>
        try {
            let dk = CoseKey.fromCborMap(issuerAuth.mso.deviceKeyInfo.deviceKey)
            msoKeyX963 = MsoValidation.toX963(dk.x, dk.y)
        } catch (e: Exception) {
            return Some(MsoValidationError.signatureVerificationFailed(
                "Cannot parse MSO deviceKey: " + e.message))
        }
        for (k in expectedDeviceKeysX963) {
            if (MsoValidation.bytesEqual(k, msoKeyX963)) {
                return None
            }
        }
        return Some(MsoValidationError.signatureVerificationFailed(
            "Device key in MSO does not match any expected holder device key"))
    }

    /** Build uncompressed x9.63 EC point bytes: 0x04 || X || Y. */
    static func toX963(x: Array<UInt8>, y: Array<UInt8>): Array<UInt8> {
        let out = Array<UInt8>(1 + x.size + y.size, repeat: 0)
        out[0] = UInt8(0x04)
        var i = 0
        while (i < x.size) {
            out[1 + i] = x[i]
            i++
        }
        var j = 0
        while (j < y.size) {
            out[1 + x.size + j] = y[j]
            j++
        }
        return out
    }

    /** Constant-length byte-array equality. */
    static func bytesEqual(a: Array<UInt8>, b: Array<UInt8>): Bool {
        if (a.size != b.size) {
            return false
        }
        var i = 0
        while (i < a.size) {
            if (a[i] != b[i]) {
                return false
            }
            i++
        }
        return true
    }

    /**
     * Full MSO validation pipeline.
     *
     * Runs all validation rules in order:
     *   1. docType check
     *   2. digestAlgorithm support check
     *   3. ValueDigests vs IssuerSignedItem digests (done_when 1)
     *   4. ValidityInfo timestamp checks (done_when 2)
     *   5. Issuer certificate chain (done_when 3)
     *
     * Collects all errors. If exactly one error, returns that error.
     * If multiple errors, returns MsoValidationError wrapping all.
     * Returns None if all checks pass.
     *
     * iOS ref: IssuerSigned.validate in MsoValidation.swift
     */
    public static func validate(
        issuerAuth: IssuerAuth,
        issuerNameSpaces: ?IssuerNameSpaces,
        expectedDocType: String,
        trustedRoots: ArrayList<Cert>,
        rejectIfValidUntilExceedsCertValidity: Bool,
        expectedDeviceKeysX963!: ?Array<Array<UInt8>> = None
    ): ?MsoValidationError {
        let mso = issuerAuth.mso
        let allErrors = ArrayList<MsoValidationError>()

        let docTypeErrOpt = MsoValidation.validateDocType(mso, expectedDocType)
        match (docTypeErrOpt) {
            case Some(e) => allErrors.add(e)
            case None => ()
        }

        let algErrOpt = MsoValidation.validateDigestAlgorithm(mso)
        match (algErrOpt) {
            case Some(e) => allErrors.add(e)
            case None => ()
        }

        match (issuerNameSpaces) {
            case Some(ns) =>
                let digestErrors = MsoValidation.validateDigestValues(mso, ns)
                for (e in digestErrors) {
                    allErrors.add(e)
                }
            case None => ()
        }

        let validityErrors = MsoValidation.validateValidityInfo(mso, issuerAuth, rejectIfValidUntilExceedsCertValidity)
        for (e in validityErrors) {
            allErrors.add(e)
        }

        let chainErrOpt = MsoValidation.validateIssuerCertChain(issuerAuth, trustedRoots)
        match (chainErrOpt) {
            case Some(e) => allErrors.add(e)
            case None => ()
        }

        let sigErrOpt = MsoValidation.validateMsoSignature(issuerAuth)
        match (sigErrOpt) {
            case Some(e) => allErrors.add(e)
            case None => ()
        }

        match (expectedDeviceKeysX963) {
            case Some(keys) =>
                let bindErrOpt = MsoValidation.validateDeviceKeyBinding(issuerAuth, keys)
                match (bindErrOpt) {
                    case Some(e) => allErrors.add(e)
                    case None => ()
                }
            case None => ()
        }

        if (allErrors.size == 0) {
            return None
        }
        if (allErrors.size == 1) {
            return Some(allErrors[0])
        }
        return Some(MsoValidationError.multipleErrors(allErrors))
    }
}
