'use strict'

/**
 * Cryptographic Message Syntax (aka PKCS #7 and RFC 5652)
 *
 * CMS describes an encapsulation syntax for data protection. It
 * is used to digitally sign, digest, authenticate, or encrypt
 * arbitrary message content.
 */
class CMS {
  /**
   * Creates a new instance with a keychain
   *
   * @param {Keychain} keychain - the available keys
   */
  constructor (keychain) {
    if (!keychain) {
      throw new Error('keychain is required')
    }

    this.keychain = keychain
  }

  /**
   * Creates some protected data.
   *
   * @param {string} name - The local key name.
   * @param {Buffer} plain - The data to encrypt.
   * @param {function(Error, Buffer)} callback
   * @returns {undefined}
   */
  encrypt (name, plain, callback) {
    throw new Error('NYI')
  }

  /**
   * Reads some protected data.
   *
   * @param {Buffer} cms - The CMS encrypted data to decrypt.
   * @param {function(Error, Buffer)} callback
   * @returns {undefined}
   */
  decrypt (cms, callback) {
    throw new Error('NYI')
  }
}

module.exports = CMS
