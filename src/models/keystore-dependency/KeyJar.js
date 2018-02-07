var KeyBundle = require('./keyBundle');
var fs = require('fs');
var shell = require('shelljs');
var URL = require('url-parse');
var RSAKey = require('./keys/RSAKey.js');

/**
 * KeyJar
 * @class
 * @constructor
 * @param {*} caCerts 
 * @param {*} verifySSL 
 * @param {*} keyBundleCls 
 * @param {*} removeAfter 
 */
function KeyJar(caCerts, verifySSL, keyBundleCls, removeAfter) {
  this.spec2key = {};
  this.issuerKeys = {};
  this.caCerts = caCerts || null;
  this.verifySSL = verifySSL || true;
  this.keyBundleCls = keyBundleCls || KeyBundle;
  this.removeAfter = removeAfter || 3600;
};

/**
 * Add a set of keys by url. This method will create a
 * :py:class:`oicmsg.oauth2.keyBundle.keyBundle` instance with the
 * url as source specification.
 * @param {*} issuer Who issued the keys
 * @param {*} url Where can the key/s be found
 * @param {*} kwargs extra parameters for instantiating keyBundle
 * @returns: A :py:class:`oicmsg.oauth2.keyBundle.keyBundle` instance
 * 
 * @memberof KeyJar
 */
KeyJar.prototype.addUrl = function(issuer, url, kwargs) {
  if (!url) {
    console.log('No jwks_uri');
  }
  var kc = null;
  if (url.indexOf('/localhost:') !== -1 || url.indexOf('/localhost/') !== -1) {
    kc = new this.keyBundleCls(source = url, verifySSL = False, kwargs);
  } else {
    kc =
        new this.keyBundleCls(source = url, verifySSL = this.verifySSL, kwargs);
  }
  if (this.issuerKeys[owner]) {
    this.issuerKeys[owner] += [kc];
  } else {
    this.issuerKeys[owner] = [kc];
  }
  return kc;
};

/**
 *  Add a symmetric key. This is done by wrapping it in a key bundle
 * cloak since KeyJar does not handle keys directly but only through
 * key bundles.
 * @param issuer Owner of the key
 * @param key The key
 * @param usage What the key can be used for signing/signature verification
 * (sig) and/or encryption/decryption (enc)
 * 
 * @memberof KeyJar
 */
KeyJar.prototype.addSymmetric = function(owner, key, usage) {
  usage = usage || null;
  if (!this.issuerKeys[owner]) {
    this.issuerKeys[owner] = [];
  }

  //_key = b64e(as_bytes(key));
  if (usage == null) {
    this.issuerKeys[owner] += new this.keyBundleCls([{'kty': 'oct', 'k': key}]);
  } else {
    for (var i = 0; i < usage.length; i++) {
      var use = usage[i];
      this.issuerKeys[owner] +=
          new this.keyBundleCls([{'kty': 'oct', 'k': key, 'use': use}]);
    }
  }
};

/**
 *  Add a key bundle and bind it to an identifier
 * @param issuer Owner of the keys in the keyBundle
 * @param kb A :py:class:`oicmsg.key_bundle.keyBundle`instance
 */
KeyJar.prototype.addKb = function(owner, kb) {
  if (this.issuerKeys[owner]) {
    this.issuerKeys[owner] += [kb];
  } else {
    this.issuerKeys[owner] = [kb];
  }
};

KeyJar.prototype.owners = function() {
  return Object.keys(this.issuerKeys);
}

/**
 * Bind one or a list of key bundles to a special identifier.
 * Will overwrite whatever was there before !!
 * @param issuer The owner of the keys in the keyBundle/-s
 * @param val A single or a list of keyBundle instance
 */
KeyJar.prototype.setItem = function(issuer, val) {
  if (!(val instanceof list)) {
    val = [val];
  }

  for (var i = 0; i < val.length; i++) {
    if (!(kb instanceof keyBundle)) {
      console.log('{} not an keyBundle instance');
    }
  }

  this.issuerKeys[owner] = val;
};

/**
 * Get all owner ID's and there key bundles
 * @return {Array} List of 2-tuples (Owner ID., list of keyBundles)
 */
KeyJar.prototype.items = function() {
  return this.issuerKeys.items();
}

/**
  * Get all keys that matches a set of search criteria
  * @param keyUser A key useful for this usage (enc, dec, sig, ver)
  * @param keyType Type of key (rsa, ec, symmetric, ..)
  * @param issuer Who is responsible for the keys, "" == me
  * @param kid A Key Identifier
  * @return: A possibly empty list of keys
  * */
KeyJar.prototype.get =
        function(keyUse, keyType, owner, kid, kwargs) {
  keyType = keyType || keyType;
  owner = owner || '';
  kid = kid || null;
  var use = '';
  if (['dec', 'enc'].indexOf(keyUse) !== -1) {
    use = 'enc';
  } else {
    use = 'sig';
  }

  var kj = null;
  if (owner !== '' && !this.issuerKeys[owner]) {
    if (owner.endsWith('/')) {
      kj = this.issuerKeys[owner.slice(0, -1)];
    } else {
      kj = this.issuerKeys[owner + '/']
    }
  } else {
    kj = this.issuerKeys[owner]
  }

  if (kj == null) {
    return [];
  }

  var lst = [];
  for (var i = 0; i < kj.length; i++) {
    var bundle = kj[i];
    var _bkeys = null;
    if (keyType) {
      _bkeys = bundle.getKty(keyType);
    } else {
      _bkeys = bundle.getKeys();
    }
    for (var i = 0; i < _bkeys.length; i++) {
      var key = _bkeys[i];
      if (key.inactiveSince && keyUse !== 'sig') {
        continue;
      }
      if (!key.use || use === key.use) {
        if (kid) {
          if (key.kid == kid) {
            lst.push(key);
            break;
          } else {
            continue;
          }
        } else {
          lst.push(key);
        }
      }
    }
  }

  // if elliptic curve have to check I have a key of the right curve
  if (keyType == 'EC' && kwargs.indexOf('alg')) {
    name = 'P-{}'.format(kwargs['alg'].slice(0, -1));  // the type
    _lst = [];
    for (var i = 0; i < lst.length; i++) {
      var key = lst[i];
      if (name != key.crv) {
        console.log('Assertion Error');
      } else {
        _lst.push(key);
      }
    }
    lst = _lst;
  }

  if (use === 'enc' && keyType === 'oct' && owner != '') {
    // Add my symmetric keys
    for (var i = 0; i < this.issuerKeys[''].length; i++) {
      var kb = this.issuerKeys[''][i];

      for (var i = 0; i < kb.getKty(keyType); i++) {
        var key = kb.getKty(keyType)[i];
        if (key.inactiveSince) {
          continue;
        }
        if (!key.use || key.use == use) {
          lst.push(key);
        }
      }
    }
  };
  return lst;

}

KeyJar.prototype.getSigningKey = function(keyType, owner, kid, args) {
  keyType = keyType || '';
  owner = owner || '';
  kid = kid || null;
  return this.get('sig', keyType, owner, kid, args);
};

KeyJar.prototype.getVerifyKey = function(keyType, owner, kid, args) {
  keyType = keyType || '';
  owner = owner || '';
  kid = kid || null;
  return this.get('ver', keyType, owner, kid, args);
};

KeyJar.prototype.getEncryptKey = function(keyType, owner, kid, args) {
  keyType = keyType || '';
  owner = owner || '';
  kid = kid || null;
  return this.get('enc', keyType, owner, kid, args);
};

KeyJar.prototype.getDecryptKey = function(keyType, owner, kid, args) {
  keyType = keyType || '';
  owner = owner || '';
  kid = kid || null;
  return this.get('dec', keyType, owner, kid, args);
};

KeyJar.prototype.getItem = function(owner) {
  try {
    return this.issuerKeys[owner];
  } catch (e) {
    if (e instanceof KeyError) {
      // Statements to handle error
      console.log('Owner not found');
    }
  };
};

KeyJar.prototype.updateKeyJar = function(keyjar) {
  for (var i = 0; i < keyjar.items().length; i++) {
    var kbl = keyjar.items()[i];
    for (var i = 0; i < kbl.length; i++) {
      var kb = kbl[i];
      kb.update();
    }
  }
};

KeyJar.prototype.matchOwner = function(url) {
  for (var i = 0; i < Object.keys(this.issuerKeys).length; i++) {
    if (url.startsWith(owner)) {
      return owner;
    }
    console.log('No keys for %s');
  }
};


/**
 * Fetch keys from another server
 * @param {*} pcr The provider information
 * @param {*} issuer The provider URL
 * @param {*} replace If all previously gathered keys from this provider should
 * be replace. :return: Dictionary with usage as key and keys as values
 */
KeyJar.prototype.loadKeys = function(pcr, issuer, replace) {
  console.log('loading keys for issuer: ' + issuer);
  if (this.issuerKeys.indexOf(replace) === -1 ||
      this.issuerKeys.indexOf(issuer) === -1) {
    this.issuerKeys[issuer] = [];
  }

  try {
    this.addUrl(issuer, pcr['jwks_uri']);
  } catch (err) {
    _keys = pcr['jwks']['keys'];
    this.issuerKeys[issuer] +=
        new this.keyBundleCls(_keys, verifySSL = this.verifySSL);
  }
};

/**
 * Find a key bundle
 * @param source A url
 * @param issuer The issuer of keys
 */
KeyJar.prototype.find = function(source, issuer) {
  for (var i = 0; i < this.issuerKeys[issuer]; i++) {
    var kb = this.issuerKeys[issuer][i];
    if (kb.source == source) {
      return kb;
    }
  }
};

KeyJar.prototype.exportJwksAsJSON = function(isPrivate, issuer) {
  return JSON.stringify(this.export_jwks(isPrivate, issuer));
};

/**
 * @param jwks Dictionary representation of a JWKS
 * @param issuer Who 'owns' the JWKS
 */
KeyJar.prototype.importJwks = function(jwks, issuer) {
  try {
    var keys = jwks['keys'];
  } catch (err) {
    console.log('Not a proper JWKS');
  }
  if (this.issuerKeys[issuer]) {
    this.issuerKeys[issuer] +=
        new this.keyBundleCls(_keys, verifySSL = this.verifySSL);
  } else {
    this.issuerKeys[issuer] =
        [new this.keyBundleCls(_keys, verifySSL = this.verifySSL)];
  }
};

KeyJar.prototype.importJwksAsJSON =
    function(js, issuer) {
  return this.importJwks(JSON.stringify(js), issuer);
}

/**
 * Initiates a new :py:class:`oicmsg.oauth2.Message` instance and
 * populates it with keys according to the key configuration.
 *
 * Configuration of the type ::
 *
 * keys = [
 *  {"type": "RSA", "key": "cp_keys/key.pem", "use": ["enc", "sig"]},
 *  {"type": "EC", "crv": "P-256", "use": ["sig"]},
 *  {"type": "EC", "crv": "P-256", "use": ["enc"]}
 * ]
 * @param {*} keyConf The key configuration
 * @param {*} kidTemplate A template by which to build the kids
 * @return A tuple consisting of a JWKS dictionary, a KeyJar instance
            and a representation of which kids that can be used for what.
            Note the JWKS contains private key information !!
 */

KeyJar.prototype.buildKeyJar = function(keyConf, kidTemplate, keyjar, kidd) {
  kidTemplate = kidTemplate || '';
  keyjar = keyjar || '';
  kidd = kidd || null;
  if (keyjar == null) {
    keyjar = new KeyJar();
  }

  if (kidd == null) {
    kidd = {'sig': {}, 'enc': {}}
  }

  var kid = 0;
  var jwks = {'keys': []}

  for (var i = 0; i < keyConf.length; i++) {
    var spec = keyConf[i];
    var typ = spec['type'].toUpperCase();

    var kb = null;
    if (typ === 'RSA') {
      if (spec['key']) {
        kb = new KeyBundle(
            source = 'file://' + spec['key'], fileformat = 'der', keytype = typ,
            keyusage = spec['use']);
      } else {
        var kb = new KeyBundle();
        kb = kb.rsaInit(spec);
      }
    } else if (typ === 'EC') {
      kb = ecInit(spec);
    }

    for (var i = 0; i < kb.keys.length; i++) {
      var k = kb.keys[i];
      if (kidTemplate) {
        k.kid = kidTemplate % kid;
        kid += 1;
      } else {
        k.kid = kid;
      }
      kidd[k.use][k.kty] = k.kid;
    }

    for (var i in kb.keys) {
      var k = kb.keys[i];
      if (k.kty !== 'oct') {
        k.serialize();
      }
    }

    // keyjar.addKb('', kb);
    return jwks, keyjar, kidd;
  }
};

KeyJar.prototype.copy = function() {
  var kj = new KeyJar();
  for (var i = 0; i < this.owners.length; i++) {
    var owner = this.owners[i];
    for (var i = 0; i < [owner].length; i++) {
      var kb = this.owner[i];
      kj[owner] = [kb.copy()];
    }
  }
  return kj;
};

KeyJar.prototype.keysByAlgAndUsage = function(issuer, alg, usage) {
  var ktype = '';
  if (['sig', 'ver'].indexOf(usage) !== -1) {
    ktype = jws.alg2keytype(alg);
  } else {
    ktype = jwe.alg2keytype(alg);
  }

  return this.get(usage, ktype, issuer);
};

KeyJar.prototype.getIssuerKeys = function(issuer) {
  var res = [];
  for (var i = 0; i < this.issuerKeys[issuer].length; i++) {
    var kbl = this.issuerKeys[issuer][i];
    res.extend(kbl.keys());
  }
  return res;
};

/**
 * Goes through the complete list of issuers and for each of them removes
 * outdated keys. Outdated keys are keys that has been marked as inactive at a
 * time that is longer ago then some set number of seconds. The number of
 * seconds a carried in the removeAfter parameter. :param when: To facilitate
 * testing
 * @param {*} when
 */
KeyJar.prototype.removeOutdated = function(when) {
  for (var i = 0; i < list(this.owners()); i++) {
    _kbl = [];
    var iss = list(this.owners)[i];
    for (var i = 0; i < this.issuerKeys[iss]; i++) {
      kb.removeOutdated(this.removeAfter, when);
      if (kb.length > 0) {
        _kbl.append(kb);
      }
    }
    if (_kbl) {
      this.issuerKeys[iss] = _kbl;
    } else {
      delete this.issuerKeys[iss];
    }
  }
};

KeyJar.prototype.addKey = function(issuer, key, keyType, kid, noKidIssuer) {
  if (this.owners.indexOf(owner) === -1) {
    console.log('Issuer not in keyjar');
    return keys;
  }

  if (kid) {
    var getVal = this.get(use, owner, kid, keyType);
    for (var i in getVal) {
      var key = getVal[i];
      if (key && this.keys.indexOf(key) === -1) {
        keys.append(_key);
      }
    }
    return keys;
  } else {
    var kl = this.get(use, owner, keyType);

    if (kl.length == 0) {
      return this.keys;
    } else if (kl.length == 1) {
      if (this.keys.indexOf(kl[0]) === -1) {
        this.keys.push(kl[0]);
      }
    } else if (no_kid_issuer) {
      try {
        var allowedKids = no_kid_issuer[owner];
      } catch (err) {
        return keys;
      }
      if (allowedKids) {
        for (var i = 0; i < kl.length; i++) {
          var k = kl[i];
          if (allowedKids.indexOf(k.kid)) {
            keys.push(k);
          }
        }
      } else {
        keys.push(kl);
      }
    }
    return keys;
  }
};

/**
 *  Clean up the path specification so it looks like something I could use.
 * @param {*} path
 */
KeyJar.prototype.properPath = function(path) {
  if (path.startsWith('./')) {
    pass;
  } else if (path.startsWith('/')) {
    path = '.' + path;
  } else if (path.startsWith('.')) {
    while (path.startsWith('.')) {
      path = path.substring(1, path.length);
    }
    if (path.startsWith('/')) {
      path = '.' + path;
    }
  } else {
    path = '.' + path;
  }
  if (!path.endsWith('/')) {
    path += '/';
  }
  return path;
};

/**
 * @param {*} vault Where the keys are kept
 * @returns {*} 2-tuple result of urlsplit and a dictionary with parameter name as
 * key and url and value
 */
KeyJar.prototype.keySetUp = function(vault, kwargs) {
  var vault_path = proper_path(vault);
  if (!fs.lstatSync(vault_path).isFile()){
    shell.mkdir('-p', localPath);
  }
  var kb = new KeyBundle()
  var usageArr = ['sig', 'enc'];
  for (var i = 0; i < usageArr.length; i++){
    var usage = usageArr[i];
    if (kwargs.indexOf(usage) !== -1){
      if (kwargs[usage] === null){
        continue;
      }
    }
    _args = kwargs[usage];
    if (_args['alg'].toUpperCase() === 'RSA'){
      try{
        //_key = rsa_load()
      }catch(err){
        var fileName = new fileName();
        fileName.write();
        _key = createAndStoreRsaKeyPair(vaultPath);
      }
      k = RSAKey(key=_key, use=usage);
      k.add_kid();
      kb.append(k);
    }
  }
  return kb;
}

/**
 * @param baseurl The base URL to which the key file names are added
 * @param localPath Where on the machine the export files are kept
 * @param vault Where the keys are kept
 * @param keyjar Where to store the exported keys
 * @returns {*} 2-tuple Result of urlsplit and a dictionary with parameter name
 * as key and url and value
 */
KeyJar.prototype.keyExport = function(baseurl, localPath, vault, keyjar, kwargs) {
  var url = new URL(baseurl);
  var path = url.pathname;
  if (path.endsWith('/')) {
    path = path.substring(0, path.length - 1);
  } else {
    path = path;
  }
  localPath = this.properPath(path + '/' + localPath)
  if (!fs.existsSync(localPath)) {
    shell.mkdir('-p', localPath);
  }
  var kb = new KeyBundle();
  try {
    keyjar[''] += [kb];
  } catch (err) {
    keyjar[''] = kb;
  }
  var exportFileName = localPath + 'jwks';
  fs.writeFile(exportFileName, kb, function(err) {
    if (err) {
      return console.log(err);
    }
    console.log('The file was saved!');
  });
  url = 'http://' + url.hostname +
      exportFileName.substring(1, exportFileName.length);
  return url;
};

/**
 * Get decryption keys from a keyjar.
 * These keys should be usable to decrypt an encrypted JWT.
 * @param jwt A jwkest.jwt.JWT instance
 * @param kwargs Other key word arguments
 * @return List of usable keys
 */
KeyJar.prototype.getJwtDecryptKeys = function(jwt, kwargs) {
  keys = [];
  var _keyType = '';

  try {
    var _keyType = jwe.alg2keytype(jwt.headers['alg']);
  } catch (err) {
    console.log('Key Error');
  }

  var _kid = '';
  try {
    _kid = jwt.header['kid'];
  } catch (err) {
    console.log('Key Error');
  }

  keys = this.addKey(keys, '', 'enc', _keyType, _kid, {'': null});
  return keys;
};

/**
 * Get keys from a keyjar. These keys should be usable to verify a signed
 * JWT. :param keyjar: A KeyJar instance :param key: List of keys to start
 * with :param jso: The payload of the JWT, expected to be a dictionary.
 * @param {*} header The header of the JWT
 * @param {*} jwt A jwkest.jwt.JWT instance
 * @param {*} kwargs Other key word arguments
 * @returns: list of usable keys
 */
KeyJar.prototype.getJwtVerifyKeys = function(key, jso, header, jwt, kwargs) {
  keys = [];
  var _keyType = '';
  try {
    _keyType = jws.alg2keytype(jwt.headers['alg']);
  } catch (err) {
    _keyType = '';
  }

  var _kid = '';
  try {
    _kid = jwt.headers['kid'];
  } catch (err) {
    console.log('KeyError');
  }

  var nki = {};
  try {
    nki = kwargs['no_kid_issuer'];
  } catch (err) {
    console.log('KeyError');
  }

  _payload = jwt.payload();

  var _iss = '';
  try {
    _iss = _payload['iss'];
  } catch (err) {
    console.log('KeyError');
  }

  if (jwt.headers.indexOf('jku') !== -1 && _iss.indexOf('jku') !== -1) {
    if (jwt.headers['jku'].indexOf(_iss) === -1) {
      try {
        if (kwargs['trusting']) {
          this.addUrl(_iss, jwt.headers['jku']);
        }
      } catch (err) {
        console.log('KeyError');
      }
    }
  }

  try {
    keys = this.addKey(keys, kwargs['opponent_id'], 'sig', _keyType, _kid, nki);
  } catch (err) {
    pass;
  }

  for (var i = 0; i < ['iss', 'aud', 'client_id'].length; i++) {
    var ent = ['iss', 'aud', 'client_id'][i];
    if (payload.indexOf(ent) === 1) {
      continue;
    }
    if (ent == 'aud') {
      if (_payload['aud'] instanceof six.string_types) {
        _aud = [_payload['aud']];
      } else {
        _aud = _payload['aud'];
      }
      for (var _e in _aud) {
        keys = this.addKey(keys, _e, 'sig', _keyType, _kid, nki);
      }
    } else {
      keys = this.addKey(keys, _payload[ent], 'sig', _keyType, _kid, nki);
    }
  }
  return keys;
};

module.exports = KeyJar;
