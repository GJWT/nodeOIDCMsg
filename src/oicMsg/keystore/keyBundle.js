const async = require('asyncawait/async');
const awaitFunc = require('asyncawait/await');
const forge = require('node-forge');
const fs = require('fs');
const jwkToPem = require('jwk-to-pem');
const path = require('path');
const shell = require('shelljs');
const XMLHttpRequest = require('xmlhttprequest').XMLHttpRequest;
const RSAKey = require('../jose/jwk/keys/RSAKey.js');
const ECKey = require('../jose/jwk/keys/ECKey.js');
const SYMKey = require('../jose/jwk/keys/SYMKey.js');
const NodeRSA = require('node-rsa');
const getPem = require('rsa-pem-from-mod-exp');

/**
 * @fileoverview Represents a set of keys with a common origin.The idea behind
 * the class is that it should be the link between a set of keys and the OIDC
 * client library. It works by on one hand keeping an internal representation of
 * the keys in sync with a specific external representation (the external
 * version representing the correct state of the key) and on the other hand
 * provide an API for accessing the keys. The reason for key sets to change are
 * regular key roll-over or as a result of key compromise.
 */

/**
 * KeyBundle
 * @class
 * @constructor
 */
class KeyBundle {
  constructor() {
    console.log('test');
  }

  getCurrentTime() {
    return Date.now();
  }

  doKeys(keyData) {
    if (!this.keys) {
      this.keys = [];
    }
    if (typeof keyData === 'string') {
      this.keys.push(keyData);
    } else {
      for (const i = 0; i < keyData.length; i++) {
        this.keys.push(keyData[i]);
      }
    }
  }

  getKty(typ = '') {
    this.upToDate();
    if (typ !== '') {
      const keysList = [];

      for (const key of this.keys) {
        if (key.kty === typ) {
          keysList.push(key);
        }
      }

      return keysList;
    } else {
      return this.keys;
    }
  }

  getKeyList(keys) {
    const keysList = [];
    const impJwks = this.getJwks();
    if (keys.length === 0 && impJwks) {
      keys = impJwks.keys;
    }
    for (const index = 0; index < keys.length; index++) {
      const key = jwkToPem(keys[index]);
      if (keys[index].inactiveSince &&
          keys[index].inactiveSince <= this.getCurrentTime()) {
        console.log(`Key not active :${keys[index]}`);
      } else {
        keysList.push(key);
      }
    }
    this.formattedKeysList = keysList;
    return keysList;
  }

  getKeysOld() {
    if (this.formattedKeysList.length !== 0) {
      return this.formattedKeysList;
    } else if (this.source !== '') {
      this.getHttpRequestResponse(this.source, args)
          .then(function(response) {
            const keys = JSON.parse(response).keys;
            return this.getKeyList(keys);
          })
          .catch(err => {console.log(`Something went wrong: ${err}`)});
    } else {
      return this.getKeyList(this.keys);
    }
  }

  getKeyWithKid(kid) {
    for (const key of this.keys) {
      if (key.kid === kid) {
        return key;
      }
    }

    this.update();

    for (const key of this.keys) {
      if (key.kid === kid) {
        return key;
      }
    }

    return null;
  }

  getJwks(isPrivate = false) {
    this.upToDate();
    const keys = [];
    const jwk = {'keys': keys};
    return JSON.stringify(jwk);
  }

  remove(key) {
    const i = this.keys.indexOf(key);
    if (i !== -1) {
      this.keys.splice(i, 1);
    }
  }

  markAsInactive(kid) {
    const k = this.getKeyWithKid(kid);
    k.inactiveSince = this.getCurrentTime();
  }

  /**
   * Reload the keys if necessary.
   * This is a forced update, will happen even if cache time has not elapsed
   * Replaced keys will be marked as inactive and not removed.
   *
   * @memberof KeyBundle
   */
  update() {
    const res = true;
    if (this.source) {
      const keys = this.keys;
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
        console.log(`Key bundle update failed: ${err}`);
        this.keys = keys;
        return false;
      }

      const now = this.getCurrentTime();

      for (const key of this.keys) {
        if (!this.keys.includes(key)) {
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
  }

  /**
   * Remove keys that should not be available any more.
   * Outdated means that the key was marked as inactive at a time
   * that was longer ago then what is given in 'after'.
   * @param {float} after The length of time the key will remain in the KeyBundle before
   * it should be removed.
   * @param {float} when To make it easier to test
   *
   * @memberof KeyBundle
   */
  removeOutdated(after, when = 0) {
    const now = this.getCurrentTime();
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
    const kl = [];

    for (const k of this.keys) {
      if (k.inactiveSince && k.inactiveSince + after < now) {
        continue;
      } else {
        kl.push(k);
      }
    }

    this.keys = kl;
  }

  doLocalJwk(filePath) {
    const self = this;
    return new Promise((resolve, reject) => {
      fs.readFile(filePath, {encoding: 'utf-8'}, function(err, data) {
        if (err) {
          console.log(err);
          reject(err);
        } else {
          const keys = JSON.parse(data).keys;
          self.doKeys(keys);
          resolve(this.keys);
          resolve(data);
          this.lastUpdated = self.getCurrentTime();
        }
      });
    });
  }

  doLocalDer(filePath, keyType, keyUsage) {
    const self = this;
    fs.readFile(filePath, {encoding: 'utf-8'}, function(err, data) {
      if (!err) {
        self.doKeys(data);
      } else {
        console.log(err);
      }
      this.lastUpdated = this.getCurrentTime();
    });
  }

  doRemote() {
    const args = {'verify': this.verifySSL};
    if (this.etag) {
      args['headers'] = {'If-None-Match': this.etag};
    }

    this.getHttpRequestResponse(this.source, args)
        .then(function(response) {
          if (response.status === 304) {
            this.timeOut = this.getCurrentTime() + this.cacheTime;
            this.lastUpdated = this.getCurrentTime();
            try {
              this.doKeys(this.impJwks['keys']);
            } catch (err) {
              console.log('No \'keys\' keyword in JWKS');
            }
          } else if (response.status === 200) {
            this.timeOut = this.getCurrentTime() + this.cacheTime;
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
        })
        .catch(err => {console.log(err)});
  }

  upToDate() {
    const res = false;
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
  }

  parseRemoteResponse(response) {
    try {
      if (response.headers['Content-Type'] !== 'application/json') {
        console.log(`Wrong Content Type${response.headers['Content-Type']}`);
      }
    } catch (err) {
      pass;
    }
    try {
      return JSON.parse(response);
    } catch (err) {
      console.log('Value error');
    }
  }

  getKeys() {
    this.upToDate();
    const keyList = [];
    for (const index = 0; index < this.keys.length; index++) {
      if (this.keys[index].inactiveSince &&
          this.keys[index].inactiveSince < this.getCurrentTime()) {
        console.log('Don\'t include inactive keys');
      } else {
        keyList.push(this.keys[index]);
      }
    }
    return keyList;
  }

  activeKeys() {
    const res = [];

    for (const key of this.keys) {
      const ias = null;
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
  }

  removeKeysByType(type) {
    const keys = this.getKty(type);
    for (const i = 0; i < keys.length; i++) {
      this.remove(keys[i]);
    }
  }

  kids() {
    this.upToDate();
    const kidsArr = [];

    for (const key of this.keys) {
      if (key.kid !== '') {
        kidsArr.push(key.kid);
      }
    }

    return kidsArr;
  }

  harmonizeUsage(fileName, typ, use) {
    if (type(use) in six.stringTypes) {
      return [MAP[use]];
    } else if (use instanceof list) {
      ul = list(MAP.keys());
      const list = [];
      const set = new Set();
      for (const u = 0; u < use.length; u++) {
        if (ul.includes(u)) {
          set.add(MAP[u]);
        }
      }
      return Array.from(set);
    }
  }

  /**
   * Create a KeyBundle based on the content in a local file
   * @param filename Name of the file
   * @param typ Type of content
   * @param usage What the key should be used for
   * @return The created KeyBundle
   *
   * @memberof KeyBundle
   */
  keybundleFromLocalFile(fileName, typ, usage) {
    if (typ.toLowerCase() === 'jwks') {
      kb = KeyBundle(null, filename, 'jwks', usage);
    } else if (typ.toLowerCase() === 'der') {
      kb = KeyBundle(null, filename, 'der', usage);
    } else {
      console.log('Unsupported key type');
    }
    return kb;
  }

  /**
   * Write a JWK to a file. Will ignore symmetric keys !!
   * @param {Array} kbl List of KeyBundles
   * @param {string} target Name of the file to which everything should be written
   * @param {boolean} private Should also the private parts be exported
   *
   * @memberof KeyBundle
   */
  dumpJwks(kbl, target, isPrivate = false) {
    const keys = [];
    for (const i = 0; i < kbl.length; i++) {
      const kb = kbl[i];
      for (const i = 0; i < kb.keys(); i++) {
        const k = kb[i];
        if (k.kty !== 'oct' && !k.inactiveSince) {
          keys += [key]
        }
      }
    }
    res = {'keys': keys};

    try {
      const file = new File(target);
      file.open('w')
    } catch (err) {
      const pathArr = target.split('/');
      const head = pathArr[0];
      shell.mkdir('-p', head);

      const file = new File(target);
      file.open('w')
    }

    const txt = JSON.stringify(res);
    file.write(txt);
    file.close();
  }

  rsaInit(spec) {
    const arg = {};
    const arr = ['name', 'path', 'size'];

    for (const param of arr) {
      try {
        arg[param] = spec[param]
      } catch (err) {
        console.log('KeyError')
      }
    }

    const kb = new KeyBundle(null, null, 'RSA', spec['use']);
    const key = null;

    for (const use of spec['use']) {
      key =
          this.createAndStoreRSAKeyPair(arg['name'], arg['path'], arg['size']);
      key.kty = 'rsa';
      key.use = use;
      kb.keys.push(new RSAKey(use, key));
    }

    return kb;
  }

  createAndStoreRSAKeyPair(name = 'oicmsg', filePath = '.', size = 2048) {
    const pair = forge.pki.rsa.generateKeyPair(size, 0x10001);
    const privKey = pair.privateKey;
    const pubKey = pair.publicKey;
    try {
      shell.mkdir('-p', filePath);
    } catch (err) {
      console.log('OSError')
    }

    if (name) {
      const pathName = path.join(filePath, name);
      fs.open(pathName, 'w', (err, file) => {
        if (err) throw err;
        fs.write(forge.pki.privateKeyToPem(privKey));
        console.log('Saved!');
      });

      const pathNamePub = path.join(pathName, '.pub')
      fs.open(pathNamePub, 'w', (err, file) => {
        if (err) throw err;
        fs.write(forge.pki.publicKeyToPem(pubKey));
        console.log('Saved!');
      });
    }
    return privKey;
  }

  fetchPubKey(response, kid) {
    const keys = JSON.parse(response).keys;
    for (const i = 0; i < keys.length; i++) {
      if (keys[i].kid == kid) {
        const pubKeyPem = getPem(keys[i].n, keys[i].e);
        console.log(pubKeyPem);
        const key = new NodeRSA(keys[i]);
        const pubKey = key.exportKey('pkcs8-public-pem');
        const keyPair = key.generateKeyPair([2048], keys[i].e);
        return pubKeyPem;
      }
    }
  }
}

/**
 * Contains a set of keys that have a common origin.
 * The sources can be several:
 * - A dictionary provided at the initialization, see keys below.
 * - A list of dictionaries provided at initialization
 * - A file containing one of: JWKS, DER encoded key
 * - A URL pointing to a webpages from which an JWKS can be downloaded
 *
 * @param {dictionary} keys A dictionary or a list of dictionaries with the keys ['kty',
   'key', 'alg', 'use', 'kid']
 * @param {string} source Where the key set can be fetch from
 * @param {string} verifySSL Verify the SSL cert used by the server
 * @param {string} fileFormat For a local file either 'jwk' or 'der'
 * @param {string} keyType Iff local file and 'der' format what kind of key it is.
 * @param {string} keyUsage What the key loaded from file should be used for.
 *
 * @memberof KeyBundle
 */
KeyBundle.prototype.init = async(function(
    keys, source, fileFormat, keyUsage, cacheTime, verifySSL, keyType) {
  console.log('constructor');
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
  const self = this;

  const result = null;
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
      const formatArr = ['rsa', 'der', 'jwks'];
      if (formatArr.includes(fileFormat.toLowerCase())) {
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
      const formatArr = ['jwks', 'jwk'];
      if (formatArr.includes(this.fileFormat)) {
        result = awaitFunc(self.doLocalJwk(self.source));

      } else if (this.fileFormat === 'der') {
        result = this.doLocalDer(this.source, this.keyType, this.keyUsage);
      }
    }
  }
  return result;
});

const MAP = {
  'dec': 'enc',
  'enc': 'enc',
  'ver': 'sig',
  'sig': 'sig'
};

KeyBundle.prototype.getHttpRequestResponse = async((url, args) => {
  const HttpClient = function() {
    this.get = (aUrl, aCallback) => {
      const anHttpRequest = new XMLHttpRequest();
      anHttpRequest.onreadystatechange = () => {
        if (anHttpRequest.readyState == 4 && anHttpRequest.status == 200)
          aCallback(anHttpRequest.responseText);
      };
      anHttpRequest.open('GET', aUrl, true);
      if (args) {
        anHttpRequest.setRequestHeader(
            'Content-type', 'application/json; charset=utf-8');
        anHttpRequest.setRequestHeader('Content-length', args.length);
        anHttpRequest.setRequestHeader('Connection', 'close');
        anHttpRequest.send(JSON.stringify(args));
      } else {
        anHttpRequest.send(null);
      }
    }
  };
  return new Promise((resolve, reject) => {
    const client = new HttpClient();
    client.get(url, (response, err) => {
      if (response) {
        resolve(response);
      } else {
        reject(err);
      }
    });
  });
});

module.exports = KeyBundle;