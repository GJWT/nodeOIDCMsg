
const Key = require('./Key');

/**
 * Key
 * @class
 * @constructor
 * @extends Key
 * JSON Web key representation of a RSA key
 */
class RSAKey extends Key {
  constructor(
      use, key, kty, alg, kid, x5c, x5t, x5u, n, e, d, p, q, dp, dq, di, qi,
      kwargs) {
    super();
    key = super(kty, alg, use, kid, key, x5c, x5t, x5u, kwargs);
    this.members.push(['n', 'e', 'd', 'p', 'q']);
    this.longs = ['n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'di', 'qi'];
    this.publicMembers.push(['n', 'e']);
    this.required = ['kty', 'n', 'e'];

    alg = alg || '';
    kid = kid || '';
    key = key || null;
    x5c = x5c || null;
    x5t = x5t || '';
    x5u = x5u || '';
    this.kty = kty || 'RSA';
    this.use = use || '';
    this.n = n || '';
    this.e = e || '';
    this.d = d || '';
    this.p = p || '';
    this.q = q || '';
    this.dp = dp || '';
    this.dq = dq || '';
    this.di = di || '';
    this.qi = qi || '';

    const hasPublicKeyParts = this.n.length > 0 && this.e.length;
    const hasX509CertChain = x5c && (x5c.length > 0);

    if (!this.key && (hasPublicKeyParts || hasX509CertChain)) {
      this.deserialize();
    } else if (this.key && !(this.n && this.e)) {
      this.split();
    }
  }

  deserialize() {
    if (this.n && this.e) {
      try {
        for (const i = 0; i < this.longs; i++) {
          const param = this.longs[i];

          // const item = getAttr(param);

          if (!item || item instanceof Number) {
            continue;
          } else {
            try {
              const val = long(deser(item));  // TODO
            } catch (err) {
              console.log(err);
            }
            setAttr(param, val);  // TODO
          }
        }

        const lst = [this.n, this.e];
        if (this.d) {
          lst.push(this.d);
        } else if (this.p) {
          lst.push(this.p);
          if (this.q) {
            lst.push(this.q);
          }
          this.key = RSA.construct(tuple(lst));  // TODO
        } else {
          this.key = RSA.construct(lst);
        }
      } catch (err) {
        console.log('Deserialization Not Possible')
      }
    } else if (this.x5c) {
      const derCert = base64.b64decode(self.x5c[0].encode('ascii'));

      if (this.x5t) {
        if (!b64d(self.x5t.encode('ascii')) ==
            hashlib.sha1(der_cert).digest()) {
          console.log('Deserialization not possible');
        }
      }
      this.key = der2rsa(der_cert);  // TODO
      this.split();
      if (this.x5c.length > 1) {
        pass
      }
    } else {
      console.log('Deserialization not possible')
    }
  };

  serialize(priv) {
    priv = priv || false;
    if (!this.key) {
      console.log('Serialization not possible');
    }
    const res = this.common();
    const set = new Set(this.publicMembers.concat(this.longs));
    const publicLongs = Array.from(set);  //
    for (const i = 0; i < publicLongs.length; i++) {
      const param = publicLongs[i];
      /*const item = getAttr(param);
      if (item){
          res[param] = longToBase64(item); //TODO
      }*/
    }

    if (priv) {
      for (const i = 0; i < this.longs.length; i++) {
        const param = this.longs[i];
        const lst = ['d', 'p', 'q', 'dp', 'dq', 'di', 'qi'];
        if (!priv && lst.indexOf(param)) {
          continue;
        }
        // const item = getAttr(param);
        if (item) {
          res[param] = longToBase64(item);
        }
      }
    }

    return res;
  };

  split() {
    this.n = this.key.n;
    this.e = this.key.e;
    try {
      this.d = this.key.d;
    } catch (err) {
      console.log('Attribute Error')
    }
    const lst = ['p', 'q'];
    for (const i = 0; i < lst.length; i++) {
      const param = lst[i];
      try {
        const val = this.key.p
      } catch (err) {
        console.log('AttributeError');
      }
      if (val) {
        if (param == 'p') {
          this.setP(val);
        } else if (param == 'q') {
          this.setQ(val);
        }
      }
    }
  }

  /**
   *  Load the key from a file.
   *  :param filename: File name
   */
  load(filename) {
    this.key = rsaLoad(filename);
    this.split();
    return this;
  }

  /**
   *   Use this RSA key
   *   :param key: An RSA key instance
   */
  loadKey(key) {
    this.key = key;
    this.split();
    return this;
  }

  /**
   * Make sure there is a key instance present that can be used for
   * encrypting/signing.
   */
  encryptionKey(kwargs) {
    if (!this.key) {
      this.deserialize();
    }
    return this.key;
  }

  getP() {
    return this.p;
  };

  setP(val) {
    this.p = val;
  };

  getQ() {
    return this.q;
  };

  setQ(val) {
    return this.q = val;
  };
}

module.exports = RSAKey;
