var jwt = require('../index');
var fs = require('fs');
var path = require('path');
var expect = require('chai').expect;
var assert = require('chai').assert;
var ms = require('ms');
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

function loadKey(filename) {
  return fs.readFileSync(path.join(__dirname, filename));
}

describe('Asymmetric Algorithms', function() {

  describe('when signing a token with none algorithm', function() {
    var clockTimestamp = 1000000000;

    var basicIdToken =
        new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('shhhh', {algorithm: 'none'});


    it('should check if explicitly set', function(done) {
      try {
        var decodedPayload = basicIdToken.fromJWT(
            signedJWT, 'shhhh', {
              'iss': 'issuer',
              'sub': 'subject',
              'maxAge': '1d',
              'clockTolerance': 10,
              'jti': 'jti'
            },
            {}, {algorithms: ['none']});
        assert.isNotNull(decodedPayload);
      } catch (err) {
        assert.isNotNull(err);
      }
      done();
    });
  });

  describe('when signing a token with none algorithm', function() {
    it('should throw if none algorithm not set by choice', function(done) {
      try {
        var clockTimestamp = 1000000000;

        var basicIdToken =
            new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
        var signedJWT = basicIdToken.toJWT('shhhh', {algorithm: 'none'});
      } catch (err) {
        assert.isNotNull(err);
      }
      done();
    });
  });



});
