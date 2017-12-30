'use strict'

const async = require('async')
const forge = require('node-forge')
const util = require('./util')

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
   * The output Buffer contains the PKCS #7 message in DER.
   *
   * @param {string} name - The local key name.
   * @param {Buffer} plain - The data to encrypt.
   * @param {function(Error, Buffer)} callback
   * @returns {undefined}
   */
  encrypt (name, plain, callback) {
    const self = this
    const done = (err, result) => async.setImmediate(() => callback(err, result))

    if (!Buffer.isBuffer(plain)) {
      return done(new Error('Plain data must be a Buffer'))
    }

    async.series([
      (cb) => self.keychain.findKeyByName(name, cb),
      (cb) => self.keychain._getPrivateKey(name, cb)
    ], (err, results) => {
      if (err) return done(err)

      let key = results[0]
      let pem = results[1]
      try {
        const privateKey = forge.pki.decryptRsaPrivateKey(pem, self.keychain._())
        util.certificateForKey(key, privateKey, (err, certificate) => {
          if (err) return callback(err)

          // create a p7 enveloped message
          const p7 = forge.pkcs7.createEnvelopedData()
          p7.addRecipient(certificate)
          p7.content = forge.util.createBuffer(plain)
          p7.encrypt()

          // convert message to DER
          const der = forge.asn1.toDer(p7.toAsn1()).getBytes()
          done(null, Buffer.from(der, 'binary'))
        })
      } catch (err) {
        done(err)
      }
    })
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
