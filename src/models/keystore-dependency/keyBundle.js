
var async = require('asyncawait/async');

var async = require('asyncawait/async');
var await = require('asyncawait/await');
var forge = require('node-forge');
var fs = require('fs');
var jwkToPem = require('jwk-to-pem');
var path = require('path');
var shell = require('shelljs');
var XMLHttpRequest = require('xmlhttprequest').XMLHttpRequest;
var RSAKey = require('./keys/RSAKey.js');
var ECKey = require('./keys/ECKey.js');
var SYMKey = require('./keys/SYMKey.js');
var NodeRSA = require('node-rsa');
var path = require('path');
var getPem = require('rsa-pem-from-mod-exp');


/**
   *  Contains a set of keys that have a common origin.
   * The sources can be several:
   * - A dictionary provided at the initialization, see keys below.
   * - A list of dictionaries provided at initialization
   * - A file containing one of: JWKS, DER encoded key
   * - A URL pointing to a webpages from which an JWKS can be downloaded
   *
   * :param keys: A dictionary or a list of dictionaries with the keys ['kty',
   'key', 'alg', 'use', 'kid']
   * :param source: Where the key set can be fetch from
   * :param verifySSL: Verify the SSL cert used by the server
   * :param fileFormat: For a local file either 'jwk' or 'der'
   * :param keyType: Iff local file and 'der' format what kind of key it is.
      presently only 'rsa' is supported.
   * :param keyUsage: What the key loaded from file should be used for.
      Only applicable for DER files
   */

function KeyBundle(){
  console.log("test");
};

KeyBundle.prototype.init = async (function(
    keys, source, fileFormat, keyUsage,
    cacheTime, verifySSL, keyType) {
  console.log("constructor");
  fileFormat = fileFormat || 'jwk';
  keyUsage = keyUsage || 'None';
  cacheTime = cacheTime || 300;
  verifySSL = keyUsage || 'None';
  keyType = keyType || 'RSA';
  source = source || '';
  this.keys = [];
  this.remote = false;
  this.verifySSL = verifySSL;
  this.cacheTime = cacheTime;
  this.timeOut = 0;
  this.etag = '';
  this.source = null;
  this.fileFormat = fileFormat.toLowerCase();
  this.keyType = keyType;
  this.keyUsage = keyUsage;
  this.impJwks = null;
  this.lastUpdated = 0;
  this.formattedKeysList = [];
  var self = this;

  var result = null;  
  if (keys) {
    if (typeof keys === 'object' && keys !== null && !(keys instanceof Array) &&
        !(keys instanceof Date)) {
      this.doKeys([keys]);
    } else {
      this.doKeys(keys);
    }
  } else {
    if (source.startsWith('file://')) {
      this.source = source.substring(7);
    } else if (source.startsWith('http://') || source.startsWith('https://')) {
      this.source = source;
      this.remote = true;
    } else if (source === '') {
      return;
    } else {
      var formatArr = ['rsa', 'der', 'jwks'];
      if (formatArr.indexOf(fileFormat.toLowerCase()) !== -1) {
        if (fs.lstatSync(source).isFile()) {
          this.source = source;
        } else {
          console.log('No such file');
        }
      } else {
        console.log('Unknown source');
      }
    }
    if (!this.remote) {
      var formatArr = ['jwks', 'jwk'];
      if (formatArr.indexOf(this.fileFormat) !== -1) {
        result = await (self.doLocalJwk(self.source));

      } else if (this.fileFormat === 'der') {
        result = this.doLocalDer(this.source, this.keyType, this.keyUsage);
      }
    }
  }
  return result;
});

var MAP = {'dec': 'enc', 'enc': 'enc', 'ver': 'sig', 'sig': 'sig'};

KeyBundle.prototype.getCurrentTime = function(){
  return Date.now();
};

KeyBundle.prototype.doKeys = function(keyData) {
  if (!this.keys){
    this.keys = [];
  }
  if (typeof keyData === 'string') {
    this.keys.push(keyData);
  } else {
    for (var i = 0; i < keyData.length; i++) {
      this.keys.push(keyData[i]);
    }
  }
};

KeyBundle.prototype.getKty = function(typ) {
  typ = typ || '';
  this.upToDate();
  if (typ !== '') {
    var keysList = [];
    for (var index = 0; index < this.keys.length; index++) {
      var key = this.keys[index];
      if (key.kty === typ){ 
        keysList.push(key);
      }
    }
    return keysList;
  } else {
    return this.keys;
  }
};

KeyBundle.prototype.getKeyList = function(keys) {
  var keysList = [];
  var impJwks = this.getJwks();
  if (keys.length === 0 && impJwks) {
    keys = impJwks.keys;
  }
  for (var index = 0; index < keys.length; index++) {
    var key = jwkToPem(keys[index]);
    if (keys[index].inactiveSince &&
        keys[index].inactiveSince <= this.getCurrentTime()) {
      console.log('Key not active :' + keys[index]);
    } else {
      keysList.push(key);
    }
  }
  this.formattedKeysList = keysList;
  return keysList;
};

KeyBundle.prototype.getKeysOld = function() {
  if (this.formattedKeysList.length !== 0) {
    return this.formattedKeysList;
  } else if (this.source !== '') {
    this.getHttpRequestResponse(this.source, args).then (function (response) { 
      var keys = JSON.parse(response).keys;
      return this.getKeyList(keys);
    }).catch(function (err) { console.log('Something went wrong: ' + err)});
  } else {
    return this.getKeyList(this.keys);
  }
};

KeyBundle.prototype.getKeyWithKid = function(kid) {
  for (var index = 0; index < this.keys.length; index++) {
    var key = this.keys[index];
    if (key.kid === kid) {
      return key;
    }
  }

  this.update();

  for (var index = 0; index < this.keys.length; index++) {
    var key = this.keys[index];
    if (key.kid === kid) {
      return key;
    }
  }

  return null;
};

KeyBundle.prototype.getJwks = function(private) {
  private = private || false;
  this.upToDate();
  var keys = [];
  var jwk = {'keys': keys};
  return JSON.stringify(jwk);
};

KeyBundle.prototype.remove = function(key) {
  var i = this.keys.indexOf(key);
  if (i !== -1) {
    this.keys.splice(i, 1);
  }
};

KeyBundle.prototype.markAsInactive = function(kid) {
  var k = this.getKeyWithKid(kid);
  k.inactiveSince = this.getCurrentTime();
};

/**
 * Reload the keys if necessary.
 * This is a forced update, will happen even if cache time has not elapsed
 * Replaced keys will be marked as inactive and not removed.
 */
KeyBundle.prototype.update = function() {
  var res = true;
  if (this.source) {
    var keys = this.keys;
    this.keys = [];

    try {
      if (this.remote === false) {
        if (this.fileFormat === 'jwks') {
          this.doLocalJwk(this.source);
        } else if (this.fileFormat === 'der') {
          this.doLocalDer(this.source, this.keyType, this.keyUsage);
        }
      } else {
        res = this.doRemote();
      }
    } catch (err) {
      console.log('Key bundle update failed: ' + err);
      this.keys = keys;
      return false;
    }

    var now = this.getCurrentTime();
    for (var index = 0; index < this.keys.length; index++) {
      var key = this.keys[index];
      if (this.keys.indexOf(key) === -1) {
        try {
          key.inactiveSince;
        } catch (err) {
          key.inactiveSince = now;
        }
        this.keys.push(key);
      }
    }
  }
  return res;
};

/**
 * Remove keys that should not be available any more.
 * Outdated means that the key was marked as inactive at a time
 * that was longer ago then what is given in 'after'.
 * :param after: The length of time the key will remain in the KeyBundle before
 * it should be removed. :param when: To make it easier to test
 */
KeyBundle.prototype.removeOutdated = function(after, when) {
  when = when || 0;
  var now = this.getCurrentTime();
  if (when) {
    now = when;
  } 
  if (!(after instanceof float)) {
    try {
      after = float(after);
    } catch (err) {
      console.log(err);
    }
  }
  var kl = [];
  for (var i = 0; i < this.keys.length; i++){
    var k = this.keys[i];
    if (k.inactiveSince && k.inactiveSince + after < now) {
      continue;
    } else {
      kl.push(k);
    }
  }
  this.keys = kl;
};

KeyBundle.prototype.doLocalJwk = function(filePath) {
  var self = this;
  return new Promise(function (resolve, reject) {
    fs.readFile(filePath, {encoding: 'utf-8'}, function(err, data) {
      if (err) {
        console.log(err);
        reject(err);
      } else {
        var keys = JSON.parse(data).keys;
        self.doKeys(keys);
        resolve(this.keys);
        resolve(data);
        this.lastUpdated = self.getCurrentTime();
      }
    });
  });
};

KeyBundle.prototype.doLocalDer = function(filePath, keyType, keyUsage) {
  var self = this;
  fs.readFile(filePath, {encoding: 'utf-8'}, function(err, data) {
    if (!err) {
      self.doKeys(data);
    } else {
      console.log(err);
    }
    this.lastUpdated = this.getCurrentTime();
  });
};

KeyBundle.prototype.doRemote = function() {
  var args = {'verify': this.verifySSL};
  if (this.etag) {
    args['headers'] = {'If-None-Match': this.etag};
  }

  this.getHttpRequestResponse(this.source, args).then (function (response) { 
    if (response.status === 304) {
      this.timeOut = this.getCurrentTime() + this.cacheTime;
      this.lastUpdated = this.getCurrentTime();
      try {
        this.doKeys(this.impJwks['keys']);
      } catch (err) {
        console.log('No \'keys\' keyword in JWKS');
      }
    } else if (response.status === 200) {
      this.timeOut = this.getCurrentTime() +
          this.cacheTime;
      this.impJwks = this.parseRemoteResponse(response);
    
      if (!(typeof this.impJwks === 'object' && this.impJwks !== null &&
            !(this.impJwks instanceof Array) &&
            !(this.impJwks instanceof Date)) &&
          !(JSON.parse(this.impJwks).keys)) {
        console.log('Malformed format for Imported JWK');
      }

      try {
        this.doKeys(JSON.parse(this.impJwks).keys);
      } catch (err) {
        console.log('No \'keys\' keyword in JWKS');
        console.log('MALFORMED FORMAT');
      }
      try {
        this.etag = response.headers['Etag'];
      } catch (err) {
        console.log('Etag err');
      }
    } else {
      console.log('Update Failed');
    }
    this.lastUpdated = this.getCurrentTime();
    return true;    
  }).catch(function (err) { console.log(err)});
};

KeyBundle.prototype.upToDate = function() {
  var res = false;
  if (this.keys !== []) {
    if (this.remote) {
      if (this.getCurrentTime() > this.timeOut) {
        if (this.update()) {
          res = true;
        }
      }
    }
  } else if (this.remote) {
    if (this.update()) {
      res = true;
    }
  }
  return res;
};

KeyBundle.prototype.parseRemoteResponse = function(response) {
  try {
    if (response.headers['Content-Type'] !== 'application/json') {
      console.log('Wrong Content Type' + response.headers['Content-Type']);
    }
  } catch (err) {
    pass;
  }
  try {
    return JSON.parse(response);
  } catch (err) {
    console.log('Value error');
  }
};

KeyBundle.prototype.getKeys = function() {
  this.upToDate();
  var keyList = [];
  for (var index = 0; index < this.keys.length; index++) {
    if (this.keys[index].inactiveSince &&
        this.keys[index].inactiveSince < this.getCurrentTime()) {
      console.log('Don\'t include inactive keys');
    } else {
      keyList.push(this.keys[index]);
    }
  }
  return keyList;
};

KeyBundle.prototype.activeKeys = function() {
  var res = [];
  for (var i = 0; i < this.keys.length; i++) {
    var key = this.keys[i];
    var ias = null;
    if (!key.inactiveSince) {
      res.push(key);
    } else {
      ias = key.inactiveSince;
      if (ias === 0) {
        res.push(key);
      }
    }
  }
  return res;
};

KeyBundle.prototype.removeKeysByType = function(type) {
  var keys = this.getKty(type);
  for (var i = 0; i < keys.length; i++) {
    this.remove(keys[i]);
  }
};

KeyBundle.prototype.kids = function() {
  this.upToDate();
  var kidsArr = [];
  for (var i = 0; i < this.keys.length; i++) {
    var key = this.keys[i];
    if (key.kid !== '') {
      kidsArr.push(key.kid);
    }
  }
  return kidsArr;
};

/**
 * :param use:
 * :return: list of usage
 */
KeyBundle.prototype.harmonizeUsage = function(fileName, typ, use) {
  if (type(use) in six.stringTypes) {
    return [MAP[use]];
  } else if (use instanceof list) {
    ul = list(MAP.keys());
    var list = [];
    var set = new Set();
    for (var u = 0; u < use.length; u++) {
      if (ul.indexOf(u) !== -1) {
        set.add(MAP[u]);
      }
    }
    return Array.from(set);
  }
};

/**
  * Create a KeyBundle based on the content in a local file
  * :param filename: Name of the file
  * :param typ: Type of content
  * :param usage: What the key should be used for
  * :return: The created KeyBundle
  */
KeyBundle.prototype.keybundleFromLocalFile = function(
        fileName, typ, usage) {
  if (typ.toLowerCase() === 'jwks') {
    kb = KeyBundle(null, filename, 'jwks', usage);
  } else if (typ.toLowerCase() === 'der') {
    kb = KeyBundle(null, filename, 'der', usage);
  } else {
    console.log('Unsupported key type');
  }
  return kb;
};

/**
 * Write a JWK to a file. Will ignore symmetric keys !!
 * :param kbl: List of KeyBundles
 * :param target: Name of the file to which everything should be written
 * :param private: Should also the private parts be exported
 */
KeyBundle.prototype.dumpJwks = function(kbl, target, private = false) {
  private = private || false;
  var keys = [];
  for (var i = 0; i < kbl.length; i++){
    var kb = kbl[i];
    for (var i = 0; i < kb.keys(); i++){
      var k = kb[i];
      if (k.kty !== 'oct' && ! k.inactiveSince){
        keys += [key]
      }
    }
  }
  res = {"keys": keys};

  try{
    var file = new File(target);
    file.open('w')
  }catch(err){
    var pathArr = target.split('/');
    var head = pathArr[0];
    shell.mkdir('-p', head);
    
    var file = new File(target);
    file.open('w')
  }

  var txt = JSON.stringify(res);
  file.write(txt);
  file.close();
};

KeyBundle.prototype.rsaInit = function(spec) {
  var arg = {}
  var arr = ["name", "path", "size"];
  for (var i =0; i < arr.length; i++){
    var param = arr[i];
      try{
          arg[param] = spec[param]
      }catch(err){
        console.log("KeyError")
      }
    }
  var kb = new KeyBundle(null, null, "RSA", spec["use"])
  var key = null;
  for (var i = 0; i < spec["use"].length; i++){
    var use = spec["use"][i];
    key = this.createAndStoreRSAKeyPair(arg['name'], arg['path'], arg['size']);
    key.kty = "rsa";
    key.use = use;
    kb.keys.push(new RSAKey(use, key));
  }
  return kb;
};

KeyBundle.prototype.createAndStoreRSAKeyPair = function(name, filePath, size) {
  name = name || "oicmsg";
  filePath = filePath || ".";
  size = size || 2048;
  var pair = forge.pki.rsa.generateKeyPair(size, 0x10001);
  var privKey = pair.privateKey;
  var pubKey = pair.publicKey;
  try{
    shell.mkdir('-p', filePath);    
  }catch(err){
    console.log("OSError")
  }

  if (name){
    var pathName = path.join(filePath, name);
    fs.open(pathName, 'w', function (err, file) {
      if (err) throw err;
      fs.write(forge.pki.privateKeyToPem(privKey));      
      console.log('Saved!');
    });
    
    var pathNamePub = path.join(pathName, ".pub")
    fs.open(pathNamePub, 'w', function (err, file) {
      if (err) throw err;
      fs.write(forge.pki.publicKeyToPem(pubKey));
      console.log('Saved!');
    });
  }
  return privKey;
};  

KeyBundle.prototype.fetchPubKey = function(response, kid){
  var keys = JSON.parse(response).keys;
  for (var i = 0; i < keys.length; i++){
    if (keys[i].kid == kid){
      var pubKeyPem = getPem(keys[i].n, keys[i].e);
      console.log(pubKeyPem);     
      var key = new NodeRSA(keys[i]);
      var pubKey = key.exportKey('pkcs8-public-pem');
      var keyPair = key.generateKeyPair([2048], keys[i].e);
      return pubKeyPem;
    }
  }
};
 
KeyBundle.prototype.getHttpRequestResponse = async (function(url, args){
  var HttpClient = function() {
    this.get = function(aUrl, aCallback) {
      var anHttpRequest = new XMLHttpRequest();
      anHttpRequest.onreadystatechange = function() { 
        if (anHttpRequest.readyState == 4 && anHttpRequest.status == 200)
          aCallback(anHttpRequest.responseText);
      }
      anHttpRequest.open( "GET", aUrl, true );            
      if (args){
        anHttpRequest.setRequestHeader(
          'Content-type', 'application/json; charset=utf-8');
        anHttpRequest.setRequestHeader('Content-length', args.length);
        anHttpRequest.setRequestHeader('Connection', 'close');
        anHttpRequest.send(JSON.stringify(args));
      } else {
        anHttpRequest.send(null);          
      }
    }
  }
  return new Promise(function (resolve, reject) {
    var client = new HttpClient();
    client.get(url, function(response, err) {
      if (response){
        resolve(response);
      } else {
        reject(err);
      }
    });
  });
});

module.exports = KeyBundle;