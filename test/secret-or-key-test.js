var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');
var assert = require('chai').assert;

describe('verifying without specified secret or public key', function() {
  var clockTimestamp = 1000000000;

  var basicIdToken = new BasicIdToken(
      {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
  basicIdToken.addOptionalClaims({
    'aud': 'audience',
    'nbf': clockTimestamp + 2,
    'exp': clockTimestamp + 3
  });
  basicIdToken.setNoneAlgorithm(true);
  it('should not verify null', function(done) {
    basicIdToken.toJWT('shhhh').then(function(signedJWT) {
      basicIdToken
          .fromJWT(
              signedJWT, null, {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '1d',
                'clockTolerance': 10,
                'jti': 'jti'
              },
              {'clockTimestamp': clockTimestamp})
          .catch(function(err) {
            assert.isNotNull(err);
          });
    });
    done();
  });

  it('should not verify undefined', function(done) {
    basicIdToken.toJWT('shhhh').then(function(signedJWT) {
      basicIdToken
          .fromJWT(
              signedJWT, {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '1d',
                'clockTolerance': 10,
                'jti': 'jti'
              },
              {'clockTimestamp': clockTimestamp})
          .catch(function(err) {
            assert.isNotNull(err);
          });
    });
    done();
  });
});