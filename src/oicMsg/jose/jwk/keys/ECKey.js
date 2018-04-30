const Key = require('./Key');

/**
 * ECKey
 * @class
 * @constructor
 * @extends Key
 */
class ECKey extends Key {
  constructor(kty, alg, use, kid, key, crv, x, y, d, curve, kwargs) {
    super();
    key =
        super(kty, alg, use, kid, key, null, null, null, kwargs);
    this.members =
            ['kty', 'alg', 'use', 'kid', 'crv', 'x', 'y', 'd'];
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
  }


  /**
   *  Starting with information gathered from the on-the-wire representation
   *  of an elliptic curve key initiate an Elliptic Curve.
   */
  deserialize() {
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
        console.log('Deserialization not possible')
      }
    }
  }

  getKey(priv, kwargs) {
    priv = priv || false;
    if (priv) {
      return this.d;
    } else {
      return this.x, this.y;
    }
  }

  serialize(priv, kwargs) {
    priv = priv || false;
    if (!this.crv && !this.curve) {
      console.log('Serialization Not Possible');
    }

    const res = this.common();
    res.update({
      'crv': this.curve.name(),
      'x': longToBase64(this.x),
      'y': longToBase64(this.y)
    })

        if (priv && this.d) {
      res['d'] = longToBase64(this.d);
    }
    return res;
  }

  loadKey(key) {
    this.curve = key;
    this.d, this.x, this.y = key.keyPair();
    return this;
  }

  decryptionKey() {
    return this.getKey(true);
  }

  encryptionKey(priv, kwargs) {
    return this.getKey(priv)
  }
}

module.exports = ECKey;