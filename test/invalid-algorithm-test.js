var fs = require('fs');
var path = require('path');
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');
var assert = require('chai').assert;

var pub = fs.readFileSync(path.join(__dirname, 'pub.pem'), 'utf8');
// priv is never used
// var priv = fs.readFileSync(path.join(__dirname, 'priv.pem'));

describe('when setting a wrong `header.alg`', function() {
  var clockTimestamp = 1000000000;

  var basicIdToken = new BasicIdToken(
      {'iss': 'issuer', 'sub': 'subject', 'iat': clockTimestamp, 'jti': 'jti'});
  basicIdToken.addOptionalClaims({
    'aud': 'audience',
    'nbf': clockTimestamp + 2,
    'exp': clockTimestamp + 3
  });
  basicIdToken.setNoneAlgorithm(true);
  // var signedJWT = basicIdToken.toJWT(pub, {algorithm: 'HS256'});

  /*
  describe('signing with pub key as symmetric', function () {
    it('should not verify', function () {
      expect(function () {
        var decodedPayload = basicIdToken.fromJWT(signedJWT, pub, {"iss" :
  "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d',
  'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});
        //jwt.verify(TOKEN, pub);
      }).to.throw(JsonWebTokenError, /invalid algorithm/);
    });
  });*/

  describe(
      'signing with pub key as HS256 and whitelisting only RS256', function() {
        it('should not verify', function(done) {
          basicIdToken.toJWT(pub, {algorithm: 'HS256'})
              .then(function(signedJWT) {
                basicIdToken
                    .fromJWT(
                        signedJWT, pub, {
                          'iss': 'issuer',
                          'sub': 'subject',
                          'aud': 'audience',
                          'maxAge': '1d',
                          'clockTolerance': 10,
                          'jti': 'jti'
                        },
                        {
                          algorithms: ['RS256'],
                          'clockTimestamp': clockTimestamp
                        })
                    .catch(function(err) {
                      assert.isNotNull(err);
                    });
              });
          done();
        });
      });

  describe('signing with HS256 and checking with HS384', function() {
    it('should not verify', function(done) {
      basicIdToken.toJWT(pub, {algorithm: 'HS256'}).then(function(signedJWT) {
        basicIdToken
            .fromJWT(
                signedJWT, pub, {
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '1d',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {algorithms: ['HS384'], 'clockTimestamp': clockTimestamp})
            .catch(function(err) {
              assert.isNotNull(err);
            });
      });
      done();
    });
  });


});
