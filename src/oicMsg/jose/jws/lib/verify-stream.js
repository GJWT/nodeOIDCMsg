/*global module*/
var base64url = require('base64url');
var DataStream = require('./data-stream');
var jwa = require('../../jwa');
var Stream = require('stream');
var toString = require('./tostring');
var util = require('util');
var JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/;
var conv = require('binstring');
var base32 = require('hi-base32');

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
  var encodedHeader = jwsSig.split('.', 1)[0];
  return safeJsonParse(base64url.decode(encodedHeader, 'binary'));
}

function headerFromJWSBase16(jwsSig) {
  var encodedHeader = jwsSig.split('.', 1)[0];
  var decodedHeader = conv(encodedHeader, {in : 'hex', out: 'binary'});
  var urlDecodedHeader = decodeURIComponent(decodedHeader);
  return JSON.parse(urlDecodedHeader);
}

function headerFromJWSBase32(jwsSig) {
  var encodedHeader = jwsSig.split('.', 1)[0];
  var decodedHeader = new Buffer(base32.decode(encodedHeader), 'binary');
  var urlDecodedHeader = decodeURIComponent(decodedHeader);

  return JSON.parse(urlDecodedHeader);
}

function securedInputFromJWS(jwsSig) {
  return jwsSig.split('.', 2).join('.');
}

function signatureFromJWS(jwsSig) {
  return jwsSig.split('.')[2];
}

/*
function signatureFromJWSBase16(jwsSig) {
  var encodedSignature = jwsSig.split('.')[2];
  return safeJsonParse(conv(encodedSignature, {in : 'hex', out: encoding}));
}*/

function payloadFromJWS(jwsSig, encoding) {
  encoding = encoding || 'utf8';
  var payload = jwsSig.split('.')[1];
  return base64url.decode(payload, encoding);
}

function payloadFromJWSBase16(jwsSig, encoding) {
  encoding = encoding || 'utf8';
  var encodedPayload = jwsSig.split('.')[1];
  var decodedPayload = conv(encodedPayload, {in : 'hex', out: encoding});
  var urlDecodedPayload = decodeURIComponent(decodedPayload);
  return urlDecodedPayload;
}

function payloadFromJWSBase32(jwsSig, encoding) {
  encoding = encoding || 'utf8';
  var encodedPayload = jwsSig.split('.')[1];
  var decodedPayload = new Buffer(base32.decode(encodedPayload), encoding);
  var urlDecodedPayload = decodeURIComponent(decodedPayload);
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
    var err = new Error('Missing algorithm parameter for jws.verify');
    err.code = 'MISSING_ALGORITHM';
    throw err;
  }
  jwsSig = toString(jwsSig);
  var signature = signatureFromJWS(jwsSig);
  var securedInput = securedInputFromJWS(jwsSig);
  var algo = jwa(algorithm, baseEncoding);
  return algo.verify(securedInput, signature, secretOrKey, baseEncoding);
}

function jwsDecode(jwtString, options) {
  options = options || {};
  var baseEncoding = options.baseEncoding || 'base64';
  if (!isValidJws(jwtString, baseEncoding)) return null;
  var header = '';
  var payload = '';
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
  var secretOrKey = opts.secret || opts.publicKey || opts.key;
  var secretStream = new DataStream(secretOrKey);
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
    var valid =
        jwsVerify(this.signature.buffer, this.algorithm, this.key.buffer);
    var obj = jwsDecode(this.signature.buffer, this.encoding);
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
