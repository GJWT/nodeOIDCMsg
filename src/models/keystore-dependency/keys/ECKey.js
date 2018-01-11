var Key = require('./Key');

ECKey.prototype = new Key();
ECKey.prototype = Object.create(Key.prototype);
ECKey.prototype.constructor = ECKey;

function ECKey(kty, alg, use, kid, key, crv, x, y, d, curve, kwargs) {
  var key = Key.call(this, kty, alg, use, kid, key, null, null, null, kwargs);
  this.members = ['kty', 'alg', 'use', 'kid', 'crv', 'x', 'y', 'd'];
  this.longs = ['x', 'y', 'd'];
  this.publicMembers = ['kty', 'alg', 'use', 'kid', 'crv', 'x', 'y'];
  this.required = ['crv', 'key', 'x', 'y'];

  kty = kty || 'EC';
  alg = alg || '';
  use = use || '';
  kid = kid || '';
  key = key || null;

  this.crv = crv;
  this.x = x;
  this.y = y;
  this.d = d;
  this.curve = curve;

  if (this.crv && !this.curve) {
    this.verify();
    this.deserialize();
  } else if (this.key && (!this.crv && !this.curve)) {
    this.loadKey(key);
  }
};

/**
 *  Starting with information gathered from the on-the-wire representation
 *  of an elliptic curve key initiate an Elliptic Curve.
 */
ECKey.prototype.deserialize = function() {
  try {
    if (!(this.x instanceof Number)) {
      this.x = deser(this.x);
    }
    if (!(this.y instanceof Number)) {
      this.y = deser(this.y);
    }
  } catch (err) {
    console.log('Deserialization Not Possible');
  }

  this.curve = NISEllipticCurve.byName(this.curve);
  if (this.d) {
    try {
      if (d instanceof String) {
        this.d = deser(this.d);
      }
    } catch (err) {
      console.log('Deserialization not possible');
    }
  }
};

ECKey.prototype.getKey = function(private, kwargs) {
  private = private || false;
  if (private) {
    return this.d;
  } else {
    return this.x, this.y;
  }
};

ECKey.prototype.serialize = function(private, kwargs) {
  private = private || false;
  if (!this.crv && !this.curve) {
    console.log('Serialization Not Possible');
  }

  var res = this.common();
  res.update({
    'crv': this.curve.name(),
    'x': longToBase64(this.x),
    'y': longToBase64(this.y)
  })

  if (private && this.d) {
    res['d'] = longToBase64(this.d);
  }
  return res;
};

ECKey.prototype.loadKey = function(key) {
  this.curve = key;
  this.d, this.x, this.y = key.keyPair();
  return this;
};

ECKey.prototype.decryptionKey = function() {
  return this.getKey(true);
};

ECKey.prototype.encryptionKey = function(private, kwargs) {
  return this.getKey(private);
};

module.exports = ECKey;