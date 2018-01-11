var Key = require('./Key');

SYMKey.prototype = new Key();
SYMKey.prototype = Object.create(Key.prototype);
SYMKey.prototype.constructor = SYMKey;

function SYMKey(kty, alg, use, kid, key, x5c, x5t, x5u, k, mtrl, kwargs) {
  var key = Key.call(this, kty, alg, use, kid, key, x5c, x5t, x5u, kwargs);
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
};

SYMKey.prototype.deserialize =
    function() {
  this.key = b64d(bytes(this.k)); 
};

YMKey.prototype.serialize = function(private) {
  private = private || true;
  res = this.common();
  res['k'] = asUnicode(b64e(bytes(this.key))); 
  return res;
}

/**
 *  Return an encryption key as per
 *  http://openid.net/specs/openid-connect-core-1_0.html#Encryption
 *
 * :param alg: encryption algorithm
 * :param kwargs:
 * :return: encryption key as byte string
 */
SYMKey.prototype.encryptionKey = function(alg, kwargs) {
  if (!this.key) {
    return this.deserialize();
  }
  var tsize = ALG2KEYLEN[alg];
  var encKey = null;
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
};

module.exports = SYMKey;