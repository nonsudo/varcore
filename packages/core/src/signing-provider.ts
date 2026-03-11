/**
 * RFC 8037 OKP JWK shape for Ed25519 public keys.
 * Defined here to avoid a dependency on DOM or WebCrypto type libs.
 */
export interface PublicKeyJwk {
  kty: "OKP";
  crv: "Ed25519";
  kid: string;
  /** Base64url-encoded 32-byte public key */
  x: string;
  use?: string;
}

/**
 * SigningProvider — abstracts the Ed25519 signing operation.
 *
 * The software path (SoftwareSigningProvider in @nonsudo/proxy) holds the
 * raw private key in memory. An HSM path (HsmSigningProvider — closed-source,
 * never published to npm) delegates to a hardware security module without ever
 * exposing the private key bytes to the process.
 *
 * Used by:
 *   - @varcore/receipts   signReceipt(receipt, provider)
 *   - @nonsudo/proxy      ProxyContext.signingProvider
 */
export interface SigningProvider {
  /**
   * Sign raw bytes and return the 64-byte Ed25519 signature.
   * The payload is the JCS-canonical UTF-8 bytes of the signing payload.
   */
  sign(payload: Uint8Array): Promise<Uint8Array>;

  /**
   * Return the public key as an RFC 8037 OKP JWK (Ed25519).
   * Used when publishing the key or building the conform test-vector file.
   */
  getPublicKeyJwk(): Promise<PublicKeyJwk>;

  /**
   * Key identifier — embedded verbatim in every SignatureBlock.key_id.
   * Must match the kid field in the JWK returned by getPublicKeyJwk().
   */
  readonly keyId: string;
}
