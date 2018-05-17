/*global module*/
const base64url = require('base64url');
const DataStream = require('./data-stream');
const jwa = require('../../jwa');
const Stream = require('stream');
const toString = require('./tostring');
const util = require('util');
const JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;
const conv = require('binstring');
const base32 = require('hi-base32');

function isObject(thing) {
  return Object.prototype.toString.call(thing) === '[object Object]';
}

function safeJsonParse(thing) {
  if (isObject(thing)) return thing;
  try {
    return JSON.parse(thing);
  } catch (e) {
    return undefined;
  }
}

function headerFromJWS(jwsSig) {
  let encodedHeader = jwsSig.split('.', 1)[0];
  return safeJsonParse(base64url.decode(encodedHeader, 'binary'));
}

function headerFromJWSBase16(jwsSig) {
  let encodedHeader = jwsSig.split('.', 1)[0];
  let decodedHeader = conv(encodedHeader, {in : 'hex', out: 'binary'});
  let urlDecodedHeader = decodeURIComponent(decodedHeader);
  return JSON.parse(urlDecodedHeader);
}

function headerFromJWSBase32(jwsSig) {
  let encodedHeader = jwsSig.split('.', 1)[0];
  let decodedHeader = new Buffer(base32.decode(encodedHeader), 'binary');
  let urlDecodedHeader = decodeURIComponent(decodedHeader);

  return JSON.parse(urlDecodedHeader);
}

function securedInputFromJWS(jwsSig) {
  return jwsSig.split('.', 2).join('.');
}

function signatureFromJWS(jwsSig) {
  return jwsSig.split('.')[2];
}

function payloadFromJWS(jwsSig, encoding) {
  encoding = encoding || 'utf8';
  let payload = jwsSig.split('.')[1];
  return base64url.decode(payload, encoding);
}

function payloadFromJWSBase16(jwsSig, encoding) {
  encoding = encoding || 'utf8';
  let encodedPayload = jwsSig.split('.')[1];
  let decodedPayload = conv(encodedPayload, {in : 'hex', out: encoding});
  let urlDecodedPayload = decodeURIComponent(decodedPayload);
  return urlDecodedPayload;
}

function payloadFromJWSBase32(jwsSig, encoding) {
  encoding = encoding || 'utf8';
  let encodedPayload = jwsSig.split('.')[1];
  let decodedPayload = new Buffer(base32.decode(encodedPayload), encoding);
  let urlDecodedPayload = decodeURIComponent(decodedPayload);
  return urlDecodedPayload;
}

function isValidJws(string, baseEncoding) {
  switch (baseEncoding) {
    case 'base16':
      return !!headerFromJWSBase16(string);
    case 'base32':
      return !!headerFromJWSBase32(string);
    default:
      return JWS_REGEX.test(string) && !!headerFromJWS(string);
  }
}

function jwsVerify(jwsSig, algorithm, secretOrKey, baseEncoding) {
  if (!algorithm) {
    let err = new Error('Missing algorithm parameter for jws.verify');
    err.code = 'MISSING_ALGORITHM';
    throw err;
  }
  jwsSig = toString(jwsSig);
  let signature = signatureFromJWS(jwsSig);
  let securedInput = securedInputFromJWS(jwsSig);
  let algo = jwa(algorithm, baseEncoding);
  return algo.verify(securedInput, signature, secretOrKey, baseEncoding);
}

function jwsDecode(jwtString, options) {
  options = options || {};
  let baseEncoding = options.baseEncoding || 'base64';
  if (!isValidJws(jwtString, baseEncoding)) return null;
  let header = '';
  let payload = '';
  switch (baseEncoding) {
    case 'base16':
      header = headerFromJWSBase16(jwtString);
      payload = payloadFromJWSBase16(jwtString);
      break;
    case 'base32':
      header = headerFromJWSBase32(jwtString);
      payload = payloadFromJWSBase32(jwtString);
      break;
    default:
      header = headerFromJWS(jwtString);
      payload = payloadFromJWS(jwtString);
  }
  if (!header) return null;

  if (header.typ === 'JWT' || options.json)
    payload = JSON.parse(payload, options.encoding);

  return {
    header: header,
    payload: payload,
    signature: signatureFromJWS(jwtString)
  };
}

/**
 * VerifyStream
 * @class
 * @constructor
 * @param {*} opts
 */
function VerifyStream(opts) {
  opts = opts || {};
  let secretOrKey = opts.secret || opts.publicKey || opts.key;
  let secretStream = new DataStream(secretOrKey);
  this.readable = true;
  this.algorithm = opts.algorithm;
  this.encoding = opts.encoding;
  this.secret = this.publicKey = this.key = secretStream;
  this.signature = new DataStream(opts.signature);
  this.secret.once('close', function() {
    if (!this.signature.writable && this.readable) this.verify();
  }.bind(this));

  this.signature.once('close', function() {
    if (!this.secret.writable && this.readable) this.verify();
  }.bind(this));
}
util.inherits(VerifyStream, Stream);
VerifyStream.prototype.verify = function verify() {
  try {
    let valid =
        jwsVerify(this.signature.buffer, this.algorithm, this.key.buffer);
    let obj = jwsDecode(this.signature.buffer, this.encoding);
    this.emit('done', valid, obj);
    this.emit('data', valid);
    this.emit('end');
    this.readable = false;
    return valid;
  } catch (e) {
    this.readable = false;
    this.emit('error', e);
    this.emit('close');
  }
};

VerifyStream.decode = jwsDecode;
VerifyStream.isValid = isValidJws;
VerifyStream.verify = jwsVerify;

module.exports = VerifyStream;
