/*global module*/
const base64url = require('base64url');
const DataStream = require('./data-stream');
const jwa = require('../../jwa');
const Stream = require('stream');
const toString = require('./tostring');
const util = require('util');
const conv = require('binstring');
const base32 = require('hi-base32');

function jwsSecuredInputBase(header, payload, encoding) {
  encoding = encoding || 'utf8';
  let encodedHeader = base64url(toString(header), 'binary');
  let encodedPayload = base64url(toString(payload), encoding);
  return util.format('%s.%s', encodedHeader, encodedPayload);
}

function jwsSecuredInputBase16(header, payload, encoding) {
  encoding = encoding || 'utf8';
  let uriEncoded = encodeURIComponent(JSON.stringify(header));
  let uriEncodedPayload = encodeURIComponent(JSON.stringify(payload));
  let encodedHeader = conv(uriEncoded, {in : 'binary', out: 'hex'});
  let encodedPayload = conv(uriEncodedPayload, {in : encoding, out: 'hex'});
  return util.format('%s.%s', encodedHeader, encodedPayload);
}

function jwsSecuredInputBase32(header, payload, encoding) {
  encoding = encoding || 'utf8';
  let uriEncoded = encodeURIComponent(JSON.stringify(header));
  let uriEncodedPayload = encodeURIComponent(JSON.stringify(payload));
  let encodedHeader = base32.encode(new Buffer(uriEncoded, 'binary'));
  let encodedPayload = base32.encode(new Buffer(uriEncodedPayload, encoding));
  return util.format('%s.%s', encodedHeader, encodedPayload);
}

function jwsSign(opts) {
  let header = opts.header;
  let payload = opts.payload;
  let secretOrKey = opts.secret || opts.privateKey;
  let encoding = opts.encoding;
  let baseEncoding = opts.baseEncoding;
  let algo = jwa(header.alg);

  let securedInput = '';
  switch (baseEncoding) {
    case 'base16':
      securedInput = jwsSecuredInputBase16(header, payload, encoding);
      break;
    case 'base32':
      securedInput = jwsSecuredInputBase32(header, payload, encoding);
      break;
    default:
      securedInput = jwsSecuredInputBase(header, payload, encoding);
  }

  let signature = algo.sign(securedInput, secretOrKey, baseEncoding);
  return util.format('%s.%s', securedInput, signature);
}

/**
 * SignStream
 * @class
 * @constructor
 * @param {*} opts
 */
function SignStream(opts) {
  let secret = opts.secret || opts.privateKey || opts.key;
  let secretStream = new DataStream(secret);
  this.readable = true;
  this.header = opts.header;
  this.encoding = opts.encoding;
  this.secret = this.privateKey = this.key = secretStream;
  this.payload = new DataStream(opts.payload);
  this.secret.once('close', function() {
    if (!this.payload.writable && this.readable) this.sign();
  }.bind(this));

  this.payload.once('close', function() {
    if (!this.secret.writable && this.readable) this.sign();
  }.bind(this));
}
util.inherits(SignStream, Stream);


SignStream.prototype.sign = function sign() {
  try {
    let signature = jwsSign({
      header: this.header,
      payload: this.payload.buffer,
      secret: this.secret.buffer,
      encoding: this.encoding,
      baseEncoding: this.baseEncoding,
    });
    this.emit('done', signature);
    this.emit('data', signature);
    this.emit('end');
    this.readable = false;
    return signature;
  } catch (e) {
    this.readable = false;
    this.emit('error', e);
    this.emit('close');
  }
};

SignStream.sign = jwsSign;

module.exports = SignStream;
