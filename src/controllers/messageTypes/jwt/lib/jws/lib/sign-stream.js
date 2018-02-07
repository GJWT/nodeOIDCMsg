/*global module*/
var base64url = require('base64url');

var DataStream = require('./data-stream');
var jwa = require('../../jwa');
var Stream = require('stream');
var toString = require('./tostring');
var util = require('util');

var conv = require('binstring');
var base32 = require('hi-base32');

function jwsSecuredInputBase(header, payload, encoding) {
  encoding = encoding || 'utf8';
  var encodedHeader = base64url(toString(header), 'binary');
  var encodedPayload = base64url(toString(payload), encoding);
  return util.format('%s.%s', encodedHeader, encodedPayload);
}

function jwsSecuredInputBase16(header, payload, encoding) {
  encoding = encoding || 'utf8';
  var uriEncoded = encodeURIComponent(JSON.stringify(header));
  var uriEncodedPayload = encodeURIComponent(JSON.stringify(payload));
  var encodedHeader = conv(uriEncoded, { in:'binary', out:'hex' });
  var encodedPayload = conv(uriEncodedPayload, { in:encoding, out:'hex' });
  return util.format('%s.%s', encodedHeader, encodedPayload);
}

function jwsSecuredInputBase32(header, payload, encoding) {
  encoding = encoding || 'utf8';
  var uriEncoded = encodeURIComponent(JSON.stringify(header));
  var uriEncodedPayload = encodeURIComponent(JSON.stringify(payload));
  var encodedHeader = base32.encode(new Buffer(uriEncoded, 'binary'));
  var encodedPayload = base32.encode(new Buffer(uriEncodedPayload, encoding));
  return util.format('%s.%s', encodedHeader, encodedPayload);
}

function jwsSign(opts) {
  var header = opts.header;
  var payload = opts.payload;
  var secretOrKey = opts.secret || opts.privateKey;
  var encoding = opts.encoding;
  var baseEncoding = opts.baseEncoding;
  var algo = jwa(header.alg);

  var securedInput = "";
  switch(baseEncoding) {
    case "base16":
        securedInput = jwsSecuredInputBase16(header, payload, encoding);
        break;
    case "base32":
        securedInput = jwsSecuredInputBase32(header, payload, encoding);
        break;
    default:
        securedInput = jwsSecuredInputBase(header, payload, encoding);
  }

  var signature = algo.sign(securedInput, secretOrKey, baseEncoding);
  return util.format('%s.%s', securedInput, signature);
}

/**
 * SignStream
 * @class
 * @constructor
 * @param {*} opts 
 */
function SignStream(opts) {
  var secret = opts.secret||opts.privateKey||opts.key;
  var secretStream = new DataStream(secret);
  this.readable = true;
  this.header = opts.header;
  this.encoding = opts.encoding;
  this.secret = this.privateKey = this.key = secretStream;
  this.payload = new DataStream(opts.payload);
  this.secret.once('close', function () {
    if (!this.payload.writable && this.readable)
      this.sign();
  }.bind(this));

  this.payload.once('close', function () {
    if (!this.secret.writable && this.readable)
      this.sign();
  }.bind(this));
}
util.inherits(SignStream, Stream);


SignStream.prototype.sign = function sign() {
  try {
    var signature = jwsSign({
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
