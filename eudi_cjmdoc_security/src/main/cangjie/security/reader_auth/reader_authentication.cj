/*
 * reader_authentication.cj — ISO 18013-5 §9.1.4 reader authentication.
 *
 * Implements:
 *   - ReaderAuthentication CBOR intermediate structure (§9.1.4)
 *   - MdocReaderAuthentication — certificate chain verification + COSE_Sign1 detached verify
 *
 * Reader authentication flow:
 *   1. The reader presents a COSE_Sign1 structure (readerAuth) in the DeviceRequest.
 *   2. The reader's certificate chain (x5chain) is extracted from the COSE_Sign1's
 *      unprotected header and verified against trusted root IACA certificates.
 *   3. The public key of the leaf certificate is extracted.
 *   4. The COSE_Sign1's detached payload is the ReaderAuthenticationBytes:
 *        ReaderAuthenticationBytes = Tag24(encoded(ReaderAuthentication))
 *        ReaderAuthentication = ["ReaderAuthentication", SessionTranscript, ItemsRequestBytes]
 *        ItemsRequestBytes = Tag24(itemsRequestRawData)
 *   5. The COSE_Sign1 detached signature is verified using ES256 and the leaf public key.
 *
 * CBOR encoding: all CBOR uses ohos_app_cangjie_eudi_cjcbor library.
 * Tag24 is TaggedVal(CborTag.ENCODED_CBOR, ByteStringVal(b)) — single layer (same pattern
 * as device_auth and session, per session fix-round-2 learnings).
 *
 * iOS sources mirrored:
 *   Sources/MdocSecurity18013/MdocReaderAuthentication/MdocReaderAuthentication.swift
 *   Sources/MdocSecurity18013/MdocReaderAuthentication/ReaderAuthentication.swift
 */
package ohos_app_cangjie_eudi_cjmdoc_security.security.reader_auth

import std.collection.ArrayList
import std.time.DateTime

import stdx.crypto.keys.ECDSAPublicKey
import stdx.crypto.common.DerBlob

import ohos_app_cangjie_eudi_cjmdoc_data_model.mdoc.core.CoseSign1

import ohos_app_cangjie_eudi_cjcbor.cbor.CborValue
import ohos_app_cangjie_eudi_cjcbor.cbor.CborTag
import ohos_app_cangjie_eudi_cjcbor.cbor.decodeCbor

import ohos_app_cangjie_eudi_cjmdoc_security.security.session.SessionTranscript
import ohos_app_cangjie_eudi_cjmdoc_security.security.device_auth.MdocAuthentication

import ohos_app_cangjie_eudi_cjx509.x509.core.Cert
import ohos_app_cangjie_eudi_cjx509.x509.core.CertError
import ohos_app_cangjie_eudi_cjx509.x509.core.verifyChain
import ohos_app_cangjie_eudi_cjx509.x509.core.hasExtendedKeyUsage
import ohos_app_cangjie_eudi_cjx509.x509.core.hasKeyUsageDigitalSignature
import ohos_app_cangjie_eudi_cjx509.x509.core.criticalExtensionOids
import ohos_app_cangjie_eudi_cjx509.x509.crl.Crl
import ohos_app_cangjie_eudi_cjx509.x509.crl.RevocationStatus

/* ==================================================================== */
/* Reader certificate constraint constants (ISO 18013-5, iOS parity)    */
/* ==================================================================== */

/**
 * mDoc reader-authentication ExtendedKeyUsage KeyPurposeId (ISO 18013-5 §B.1.4).
 * The reader's leaf certificate MUST assert this EKU.
 */
let MDOC_READER_AUTH_EKU_OID: String = "1.0.18013.5.1.6"

/* ==================================================================== */
/* ReaderAuthentication — §9.1.4 intermediate structure                 */
/* ==================================================================== */

/**
 * ReaderAuthentication CBOR intermediate structure (§9.1.4).
 *
 * This structure is not transferred on the wire; it is only computed locally
 * to form the COSE_Sign1 detached payload.
 *
 * CBOR encoding:
 *   ["ReaderAuthentication", SessionTranscript, ItemsRequestBytes]
 *   where ItemsRequestBytes = Tag24(itemsRequestRawData)
 *
 * The COSE payload is:
 *   ReaderAuthenticationBytes = Tag24(encoded(ReaderAuthentication))
 *
 * iOS: ReaderAuthentication struct in ReaderAuthentication.swift
 */
public class ReaderAuthentication {
    /** Session transcript for this authentication round. */
    public let sessionTranscript: SessionTranscript
    /**
     * Raw bytes of the ItemsRequest as received from the reader
     * (the original untagged CBOR bytes of the ItemsRequest map).
     * These are wrapped in Tag24 inside the ReaderAuthentication array.
     */
    public let itemsRequestRawData: Array<UInt8>

    /**
     * Create a ReaderAuthentication.
     *
     * @param sessionTranscript    Session transcript.
     * @param itemsRequestRawData  Raw CBOR bytes of the ItemsRequest.
     *
     * iOS: ReaderAuthentication(sessionTranscript:itemsRequestRawData:)
     */
    public init(
        sessionTranscript: SessionTranscript,
        itemsRequestRawData: Array<UInt8>
    ) {
        this.sessionTranscript = sessionTranscript
        this.itemsRequestRawData = itemsRequestRawData
    }

    /**
     * Encode the ReaderAuthentication array as CBOR bytes.
     *
     * ["ReaderAuthentication", SessionTranscript, Tag24(itemsRequestRawData)]
     *
     * iOS: toCBOR in ReaderAuthentication.swift (the extension CBOREncodable)
     */
    public func toCborBytes(): Array<UInt8> {
        let items = ArrayList<CborValue>()
        // [0] "ReaderAuthentication" label
        items.add(CborValue.TextStringVal("ReaderAuthentication"))
        // [1] SessionTranscript as CBOR array(3) (same as DeviceAuthentication pattern)
        let stBytes = sessionTranscript.toCborBytes()
        items.add(decodeCbor(stBytes))
        // [2] ItemsRequestBytes = Tag24(itemsRequestRawData)
        items.add(CborValue.TaggedVal(CborTag.ENCODED_CBOR, CborValue.ByteStringVal(itemsRequestRawData)))
        return CborValue.ArrayVal(items).encode()
    }

    /**
     * ReaderAuthenticationBytes = Tag24(encoded(ReaderAuthentication)).
     * This is the DETACHED payload for the reader's COSE_Sign1.
     *
     * iOS: toCBOR.taggedEncoded.encode() pattern
     */
    public func toTaggedBytes(): Array<UInt8> {
        return CborValue.TaggedVal(
            CborTag.ENCODED_CBOR,
            CborValue.ByteStringVal(this.toCborBytes())
        ).encode()
    }
}

/* ==================================================================== */
/* MdocReaderAuthentication — reader auth verification main class       */
/* ==================================================================== */

/**
 * Implements ISO 18013-5 §9.1.4 mDoc reader authentication (mdoc-side verification).
 *
 * The reader authenticates to the mdoc holder by:
 *   1. Presenting a COSE_Sign1 structure (readerAuth) with a detached payload.
 *   2. Providing an x5chain of DER-encoded certificates (leaf first).
 *   3. The holder verifies the certificate chain against trusted root IACA certs.
 *   4. The holder extracts the leaf public key and verifies the COSE_Sign1 signature
 *      over ReaderAuthenticationBytes (Tag24 of the ReaderAuthentication CBOR array).
 *
 * iOS: MdocReaderAuthentication struct in MdocReaderAuthentication.swift
 */
public class MdocReaderAuthentication {
    /** Session transcript bound to this authentication instance. */
    public let sessionTranscript: SessionTranscript

    /**
     * Create a MdocReaderAuthentication bound to the given session transcript.
     *
     * @param sessionTranscript  Session transcript from SessionEncryption.
     *
     * iOS: init(transcript:)
     */
    public init(sessionTranscript: SessionTranscript) {
        this.sessionTranscript = sessionTranscript
    }

    /**
     * Validate the reader leaf certificate's constraints (iOS isMdocX5cValid parity).
     *
     * This is the certificate-level half of ISO 18013-5 reader authentication that
     * pure chain-validation does NOT cover. iOS SecurityHelpers.isMdocX5cValid hard-fails
     * a reader certificate that does not assert the mdocReaderAuth EKU, does not assert the
     * keyUsage digitalSignature bit, or carries any of the disallowed critical extensions.
     *
     * Checks (in order; first failure returned):
     *   1. ExtendedKeyUsage MUST contain mdocReaderAuth KeyPurposeId (1.0.18013.5.1.6).
     *   2. KeyUsage MUST assert the digitalSignature bit.
     *   3. The certificate MUST NOT mark any of the following extensions critical
     *      (denylist, mirroring iOS): policyMappings (2.5.29.33), nameConstraints
     *      (2.5.29.30), policyConstraints (2.5.29.36), inhibitAnyPolicy (2.5.29.54),
     *      freshestCRL (2.5.29.46). A reader leaf bearing any of these as critical is
     *      rejected because this verifier does not process them and RFC 5280 §4.2
     *      requires a relying party to reject unhandled critical extensions.
     *
     * @param leafCert  The already-parsed reader leaf certificate (x5chain[0]).
     * @return (isValid, reason)
     *   - (true, "")            all constraints satisfied.
     *   - (false, description)  first violated constraint.
     */
    public func validateReaderCertConstraints(leafCert: Cert): (Bool, String) {
        // (1) mdocReaderAuth EKU
        if (!hasExtendedKeyUsage(leafCert, MDOC_READER_AUTH_EKU_OID)) {
            return (false, "reader cert missing mdocReaderAuth EKU (${MDOC_READER_AUTH_EKU_OID})")
        }
        // (2) keyUsage digitalSignature
        if (!hasKeyUsageDigitalSignature(leafCert)) {
            return (false, "reader cert keyUsage missing digitalSignature")
        }
        // (3) disallowed critical extensions (denylist).
        let critOids: Array<String>
        try {
            critOids = criticalExtensionOids(leafCert)
        } catch (e: CertError) {
            return (false, "reader cert critical-extension parse failed: ${e.message}")
        } catch (e: Exception) {
            return (false, "reader cert critical-extension parse failed: ${e.message}")
        }
        let denylist: Array<String> = [
            "2.5.29.33", // policyMappings
            "2.5.29.30", // nameConstraints
            "2.5.29.36", // policyConstraints
            "2.5.29.54", // inhibitAnyPolicy
            "2.5.29.46"  // freshestCRL
        ]
        for (oid in critOids) {
            for (bad in denylist) {
                if (oid == bad) {
                    return (false, "reader cert has disallowed critical extension: ${oid}")
                }
            }
        }
        (true, "")
    }

    /**
     * Verify the reader authentication.
     *
     * Steps:
     *   1. Parse the leaf certificate from x5chainDer[0] via Cert.fromDer.
     *   2. Parse intermediates from x5chainDer[1..] and roots from rootIacaDer[].
     *   3. Verify certificate chain: verifyChain(leaf, intermediates, roots).
     *   4. Extract the leaf public key as a DER-encoded SPKI blob.
     *   5. Decode to ECDSAPublicKey via ECDSAPublicKey.decodeDer(DerBlob(spkiBytes)).
     *   6. Build ReaderAuthenticationBytes = Tag24(ReaderAuthentication CBOR).
     *   7. Verify the COSE_Sign1 detached signature using MdocAuthentication.verifyDetachedCoseSign1.
     *
     * @param readerAuthCose       The COSE_Sign1 structure (4-element array, no outer tag 18).
     * @param x5chainDer           DER-encoded certificate bytes, leaf first.
     *                             x5chainDer[0] = leaf (reader cert), rest = intermediates.
     * @param itemsRequestRawData  Raw bytes of the ItemsRequest CBOR (untagged).
     * @param rootIacaDer          DER-encoded trusted root IACA certificates.
     * @param requireReaderConstraints
     *                             Opt-in (default false). When true, after a successful
     *                             chain verification the leaf certificate is additionally
     *                             gated through validateReaderCertConstraints (mdocReaderAuth
     *                             EKU + keyUsage digitalSignature + disallowed-critical-extension
     *                             denylist). A real mDoc presentation flow MUST pass true here;
     *                             it defaults to false only so that pre-existing callers/tests
     *                             that use non-conformant self-signed certs are not broken.
     * @param readerCrlDer         Opt-in (default None). DER bytes of a CRL covering the reader
     *                             leaf. When BOTH readerCrlDer and now are provided, the leaf's
     *                             serial is checked against the CRL via Crl.checkRevocation
     *                             (fail-closed: Revoked or Unverified(_) both reject; only Valid
     *                             passes). The issuer CA used to verify the CRL is taken from
     *                             rootIacaDer[0] — a simplification that holds for the common
     *                             single-IACA EUDI topology where the root signs the reader CRL.
     * @param now                  Opt-in (default None). Reference time for the CRL validity
     *                             window. Only consulted when readerCrlDer is also provided.
     *
     * @return (isValid, validationMessage)
     *   - isValid: true if chain is valid AND signature is valid (AND, when opted in,
     *     reader constraints hold and the leaf is not revoked).
     *   - validationMessage: "" on success, error description on failure.
     *
     * Throws MdocValidationError on structural CBOR issues.
     *
     * iOS: validateReaderAuth(readerAuthCBOR:readerAuthX5c:itemsRequestRawData:rootIaca:)
     */
    public func verify(
        readerAuthCose: CoseSign1,
        x5chainDer: Array<Array<UInt8>>,
        itemsRequestRawData: Array<UInt8>,
        rootIacaDer: Array<Array<UInt8>>,
        requireReaderConstraints!: Bool = false,
        readerCrlDer!: ?Array<UInt8> = None,
        now!: ?DateTime = None
    ): (Bool, String) {
        // --- Step 1: Check certificate chain is non-empty ---
        if (x5chainDer.size == 0) {
            return (false, "Invalid reader Auth Certificate: empty x5chain")
        }

        // --- Step 2: Parse leaf certificate ---
        let leafCert: Cert
        try {
            leafCert = Cert.fromDer(x5chainDer[0])
        } catch (e: CertError) {
            return (false, "Invalid reader Auth Certificate: ${e.message}")
        } catch (e: Exception) {
            return (false, "Invalid reader Auth Certificate: ${e.message}")
        }

        // --- Step 3: Parse intermediate certificates (x5chain[1..]) ---
        let intermediates = ArrayList<Cert>()
        var ci: Int64 = 1
        while (ci < x5chainDer.size) {
            try {
                let c = Cert.fromDer(x5chainDer[ci])
                intermediates.add(c)
            } catch (e: CertError) {
                return (false, "Invalid reader Auth Certificate (intermediates[${ci}]): ${e.message}")
            } catch (e: Exception) {
                return (false, "Invalid reader Auth Certificate (intermediates[${ci}]): ${e.message}")
            }
            ci += 1
        }
        let intermediateArr = intermediates.toArray()

        // --- Step 4: Parse root IACA certificates ---
        let roots = ArrayList<Cert>()
        var ri: Int64 = 0
        while (ri < rootIacaDer.size) {
            try {
                let r = Cert.fromDer(rootIacaDer[ri])
                roots.add(r)
            } catch (e: CertError) {
                return (false, "Invalid root IACA certificate [${ri}]: ${e.message}")
            } catch (e: Exception) {
                return (false, "Invalid root IACA certificate [${ri}]: ${e.message}")
            }
            ri += 1
        }
        if (roots.size == 0) {
            return (false, "No trusted root IACA certificates provided")
        }
        let rootArr = roots.toArray()

        // --- Step 5: Verify certificate chain ---
        let chainValid: Bool
        try {
            chainValid = verifyChain(leafCert, intermediateArr, rootArr)
        } catch (e: CertError) {
            return (false, "Certificate chain validation failed: ${e.message}")
        } catch (e: Exception) {
            return (false, "Certificate chain validation failed: ${e.message}")
        }

        // --- Step 6: Extract reader public key from leaf certificate ---
        // cert.publicKeyDer is the SubjectPublicKeyInfo (SPKI) DER — same format as
        // ECDSAPublicKey.decodeDer expects.
        let spkiBytes = leafCert.publicKeyDer
        let readerPubKey: ECDSAPublicKey
        try {
            readerPubKey = ECDSAPublicKey.decodeDer(DerBlob(spkiBytes))
        } catch (e: Exception) {
            return (false, "Public key not found in certificate: ${e.message}")
        }

        // --- Step 7: Build ReaderAuthenticationBytes (detached payload) ---
        let readerAuth = ReaderAuthentication(sessionTranscript, itemsRequestRawData)
        let payloadBytes = readerAuth.toTaggedBytes()

        // --- Step 8: Verify COSE_Sign1 detached signature ---
        // Reuse MdocAuthentication.verifyDetachedCoseSign1 (ES256):
        //   reattach payload, compute Sig_Structure, verify EcdsaP256
        let sigValid = MdocAuthentication.verifyDetachedCoseSign1(readerAuthCose, payloadBytes, readerPubKey)
        if (!sigValid) {
            return (false, "Reader auth signature validation failed")
        }

        // Both chain and signature are valid
        if (!chainValid) {
            return (false, "Reader auth certificate chain validation failed")
        }

        // --- Step 9: Reader certificate constraint gating (opt-in, iOS parity) ---
        // Closes the "reader auth downgraded to plain chain validation" gap: a real
        // presentation flow passes requireReaderConstraints=true so the leaf must assert
        // mdocReaderAuth EKU + keyUsage digitalSignature and carry no disallowed critical
        // extension. Default false preserves legacy/self-signed-cert callers.
        if (requireReaderConstraints) {
            let (constraintsOk, constraintMsg) = validateReaderCertConstraints(leafCert)
            if (!constraintsOk) {
                return (false, constraintMsg)
            }
        }

        // --- Step 10: CRL revocation check (opt-in, fail-closed) ---
        // Only runs when BOTH a CRL and a reference time are supplied. The issuer CA for
        // the CRL is rootIacaDer[0] (single-IACA simplification, see param doc). Any non-Valid
        // result (Revoked or Unverified(_)) rejects.
        match ((readerCrlDer, now)) {
            case (Some(crlBytes), Some(refTime)) =>
                let crl: Crl
                try {
                    crl = Crl.fromDer(crlBytes)
                } catch (e: Exception) {
                    return (false, "Reader CRL parse failed: ${e.message}")
                }
                // rootArr is guaranteed non-empty here (roots.size == 0 rejected at Step 4).
                let crlIssuer = rootArr[0]
                match (crl.checkRevocation(leafCert.serialNumber, crlIssuer, refTime)) {
                    case RevocationStatus.Revoked =>
                        return (false, "Reader certificate revoked (serial ${leafCert.serialNumber})")
                    case RevocationStatus.Unverified(why) =>
                        return (false, "Reader CRL could not be trusted: ${why}")
                    case RevocationStatus.Valid => ()
                }
            case _ => ()
        }

        return (true, "")
    }

    /**
     * Verify only the COSE_Sign1 detached signature against the leaf public
     * key. Chain trust is left to the caller (iOS `trustValidator`).
     */
    public func verifySignature(
        readerAuthCose: CoseSign1,
        x5chainDer: Array<Array<UInt8>>,
        itemsRequestRawData: Array<UInt8>
    ): (Bool, String) {
        if (x5chainDer.size == 0) {
            return (false, "Invalid reader Auth Certificate: empty x5chain")
        }
        let leafCert: Cert
        try {
            leafCert = Cert.fromDer(x5chainDer[0])
        } catch (e: CertError) {
            return (false, "Invalid reader Auth Certificate: ${e.message}")
        } catch (e: Exception) {
            return (false, "Invalid reader Auth Certificate: ${e.message}")
        }
        let spkiBytes = leafCert.publicKeyDer
        let readerPubKey: ECDSAPublicKey
        try {
            readerPubKey = ECDSAPublicKey.decodeDer(DerBlob(spkiBytes))
        } catch (e: Exception) {
            return (false, "Public key not found in certificate: ${e.message}")
        }
        let readerAuth = ReaderAuthentication(sessionTranscript, itemsRequestRawData)
        let payloadBytes = readerAuth.toTaggedBytes()
        let sigValid = MdocAuthentication.verifyDetachedCoseSign1(
            readerAuthCose,
            payloadBytes,
            readerPubKey
        )
        if (!sigValid) {
            return (false, "Reader auth signature validation failed")
        }
        (true, "")
    }
}
