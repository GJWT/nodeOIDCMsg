var Key = require('./Key');

/**
 *  JSON Web key representation of a RSA key
 */
RSAKey.prototype = new Key();
RSAKey.prototype = Object.create(Key.prototype);
RSAKey.prototype.constructor = RSAKey;

function RSAKey(use, key, kty, alg, kid, x5c, x5t, x5u, n, e, d, p, q, dp, dq, di, qi,
    kwargs) {
  var key = Key.call(this, kty, alg, use, kid, key, x5c, x5t, x5u, kwargs);
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

  var hasPublicKeyParts = this.n.length > 0 && this.e.length;
  var hasX509CertChain = x5c && (x5c.length > 0);

  if (!this.key && (hasPublicKeyParts || hasX509CertChain)) {
    this.deserialize();
  } else if (this.key && !(this.n && this.e)) {
    this.split();
  }
}

RSAKey.prototype.deserialize = function() {
  if (this.n && this.e) {
    try {
      for (var i = 0; i < this.longs; i++) {
        var param = this.longs[i];
        // var item = getAttr(param);
        if (!item || item instanceof Number) {
          continue;
        } else {
          try {
            var val = long(deser(item));  // TODO
          } catch (err) {
            console.log(err);
          }
          setAttr(param, val);  // TODO
        }
      }

      var lst = [this.n, this.e];
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
      console.log('Deserialization Not Possible');
    }
  } else if (this.x5c) {
    var derCert = base64.b64decode(self.x5c[0].encode('ascii'));
    if (this.x5t) {
      if (!b64d(self.x5t.encode('ascii')) == hashlib.sha1(der_cert).digest()) {
        console.log('Deserialization not possible');
      }
    }
    this.key = der2rsa(der_cert);  // TODO
    this.split();
    if (this.x5c.length > 1) {
      pass
    }
  } else {
    console.log('Deserialization not possible');
  }
};

RSAKey.prototype.serialize = function(private) {
  private = private || false;
  if (!this.key) {
    console.log('Serialization not possible');
  }
  var res = this.common();
  var set = new Set(this.publicMembers.concat(this.longs));
  var publicLongs = Array.from(set);
  for (var i = 0; i < publicLongs.length; i++) {
    var param = publicLongs[i];
    var item = getAttr(param);
    if (item){
        res[param] = longToBase64(item); 
    }
  }
  if (private) {
    for (var i = 0; i < this.longs.length; i++) {
      var param = this.longs[i];
      var lst = ['d', 'p', 'q', 'dp', 'dq', 'di', 'qi'];
      if (!private && lst.indexOf(param)) {
        continue;
      }
      var item = getAttr(param);
      if (item) {
        res[param] = longToBase64(item);
      }
    }
  }
  return res;
};

RSAKey.prototype.split = function() {
  this.n = this.key.n;
  this.e = this.key.e;
  try {
    this.d = this.key.d;
  } catch (err) {
    console.log('Attribute Error');
  }
  var lst = ['p', 'q'];
  for (var i = 0; i < lst.length; i++) {
    var param = lst[i];
    try {
      var val = this.key.p;
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
};

/**
 *  Load the key from a file.
 *  :param filename: File name
 */
RSAKey.prototype.load = function(filename) {
  this.key = rsaLoad(filename);
  this.split();
  return this;
};

/**
  *   Use this RSA key
  *   :param key: An RSA key instance
  */
RSAKey.prototype.loadKey = function(key) {
  this.key = key;
  this.split();
  return this;
};

/**
  * Make sure there is a key instance present that can be used for
  * encrypting/signing.
  */
RSAKey.prototype.encryptionKey = function(kwargs) {
  if (!this.key) {
    this.deserialize();
  }
  return this.key;
};

RSAKey.prototype.getP = function() {
  return this.p;
};

RSAKey.prototype.setP = function(val) {
  this.p = val;
};

RSAKey.prototype.getQ = function() {
  return this.q;
};

RSAKey.prototype.setQ = function(val) {
  return this.q = val;
};

module.exports = RSAKey;