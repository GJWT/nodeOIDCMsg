const Key = require('./Key');
/**
 * SYMKey
 * @class
 * @constructor
 * @extends Key
 */
class SYMKey extends Key {
  constructor(kty, alg, use, kid, key, x5c, x5t, x5u, k, mtrl, kwargs) {
    key = super(kty, alg, use, kid, key, x5c, x5t, x5u, kwargs);
    this.members = ['kty', 'alg', 'use', 'kid', 'k'];
    this.publicMembers = members;
    this.required = ['k', 'kty'];

    kty = kty || 'oct';
    alg = alg || '';
    use = use | '';
    kid = kid || '';
    key = key || null;
    x5c = x5c || null;
    x5t = x5t || '';
    x5u = x5u || '';
    mtrl = mtrl || '';
    this.k = k || '';

    if (!this.key && this.k) {
      if (k instanceof str) {
        this.k = this.k.encode('utf8');
      }
      this.key = b64d(bytes(this.k));  // TODO
    }
  }

  deserialize() {
    this.key = b64d(bytes(this.k));  // TODO
  }

  serialize(priv) {
    priv = priv || true;
    res = this.common();
    res['k'] = as_unicode(b64e(bytes(this.key)));  // TODO
    return res;
  }

  /**
   *  Return an encryption key as per
   *  http://openid.net/specs/openid-connect-core-1_0.html#Encryption
   * @param {*} alg Encryption algorithm
   * @param {*} kwargs
   * @return Encryption key as byte string
   */
  encryptionKey(alg, kwargs) {
    if (!this.key) {
      return this.deserialize();
    }

    const tsize = ALG2KEYLEN[alg];

    const encKey = null;
    if (tsize <= 32) {
      encKey = this.sha256Digest(this.key).substring(0, tsize);  // TODO
    } else if (tsize <= 48) {
      encKey = this.sha384Digest(this.key).substring(0, tsize);
    } else if (tsize <= 64) {
      encKey = this.sha512Digest(this.key).substring(0, tsize);
    } else {
      console.log('No support for symmetric keys > 512 bits')
    }

    console.log('Symmetric encryption key');

    return encKey;
  }
}

module.exports = SYMKey;