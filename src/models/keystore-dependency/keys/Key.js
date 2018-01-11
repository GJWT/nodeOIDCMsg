
function Key(kty, alg, use, kid, key, x5c, x5t, x5u, kwargs) {
  this.members = ['kty', 'alg', 'use', 'kid', 'x5c', 'x5t', 'x5u'];
  this.longs = [];
  this.publicMembers = ['kty', 'alg', 'use', 'kid', 'x5c', 'x5t', 'x5u'];
  this.required = ['kty'];

  kty = kty || '';
  alg = alg || '';
  use = use || '';
  kid = kid || '';
  x5c = x5c || null;
  x5t = x5t || '';
  x5u = x5u || '';

  this.key = key || null;
  this.extraArgs = kwargs;

  if (typeof kty === 'string') {
    this.kty = kty;
  } else {
    this.kty = kty.decode('utf8');  // TODO
  }

  if (typeof alg === 'string') {
    this.alg = alg;
  } else {
    this.alg = alg.decode('utf8');
  }

  if (typeof use === 'string') {
    this.use = use;
  } else {
    this.kid = kid.decode('utf8');
  }

  this.x5c = x5c || [];
  this.x5t = x5t || '';
  this.x5u = x5u || '';
  this.inactiveSince = 0;
};

Key.prototype.toDict = function() {
  var res = this.serialize(true);
  res.update(this.extraArgs);
  return res;
};

Key.prototype.common = function() {
  var res = {'kty': this.kty};
  if (this.use) {
    res['use'] = this.use;
  }
  if (this.kid) {
    res['kid'] = this.kid;
  }
  if (this.alg) {
    res['alg'] = this.alg;
  }
  return res;
};

Key.prototype.deserialize = function() {};

Key.prototype.serialize = function() {};

Key.prototype.getKey = function() {
  return this.key;
};

Key.prototype.verify = function() {
  for (var i = 0; i < this.longs.length; i++) {
    var item = this.getAttr(param);
    if (!item || item instanceof Number) {
      continue;
    }
    if (item instanceof bytes) {
      item = item.decode('utf-8');
      this.setAttr(param, item);
    }

    try {
      var b64ToLong = base64UrlToLong(item);
    } catch (err) {
      return false;
    }

    var operators = ['+', '/', '='];
    for (var i = 0; i < operators.length; i++) {
      if (item.indexOf(e) !== -1) {
        if ([e]) {
          return false;
        }
      }
    }

    if (this.kid) {
      try {
        var instanceOfStr = (this.kid instanceof String)
      } catch (err) {
        console.log('Kid of wrong value type')
      }
    }
    return true;
  }
};

Key.prototype.equals = function(other) {
  try {
    if (key instanceof other &&
        set(Object.keys(this.dict) == set(other.dict.keys()))) {
      for (var i = 0; i < this.publicMembers.length; i++) {
        if (this.getAttr(other, key) == this.getAttr(key)) {
          return true;
        }
      }
    }
  } catch (err) {
    console.log('Assertion Error');
  }
};

Key.prototype.keys = function() {
  return list(Object.keys(this.toDict()));
};

Key.prototype.thumbprint = function(hashFunction, members) {
  members = members || null;
  if (members === null) {
    members = this.required;
  }

  members.sort();
  var ser = this.serialize();
  var se = [];
  for (var i = 0; i < members.length; i++) {
    var elem = this.members[i];
    try {
      var val = ser[elem];
    } catch (err) {
      console.log('Key Error')
    }
    se.push(JSON.stringify({elem: {}}));
  }

  return DIGEST_HASH[hash_function](_json);  // TODO
};

Key.prototype.addKid = function() {
  this.kid = b64e(self.thumbprint('SHA-256')).decode('utf8');
};

Key.prototype.deser = function() {
  var val = null;
  if (val instanceof str) {
    val = val.encode('utf-8');
  } else {
    val = val;
  }
  return base64ToLong(val);
};

module.exports = Key;