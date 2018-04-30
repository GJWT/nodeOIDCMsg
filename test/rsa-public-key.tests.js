var fs = require('fs');
var clockTimestamp = 1000000000;
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');
var assert = require('chai').assert;

describe('public key start with BEGIN RSA PUBLIC KEY', function() {

  it('should work', function(done) {
    var cert_pub = fs.readFileSync(__dirname + '/rsa-public-key.pem');
    var cert_priv = fs.readFileSync(__dirname + '/rsa-private.pem');

    var basicIdToken = new BasicIdToken(
        {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
    basicIdToken.addOptionalClaims({
      'foo': 'bar',
      'aud': 'audience',
      'nbf': clockTimestamp + 2,
      'exp': clockTimestamp + 3
    });
    basicIdToken.setNoneAlgorithm(true);
    basicIdToken.toJWT(cert_priv, {algorithm: 'RS256'})
        .then(function(signedJWT) {
          basicIdToken
              .fromJWT(
                  signedJWT, cert_pub, {
                    'iss': 'issuer',
                    'sub': 'subject',
                    'aud': 'audience',
                    'maxAge': '1d',
                    'clockTolerance': 10,
                    'jti': 'jti'
                  },
                  {'clockTimestamp': clockTimestamp}, done)
              .catch(function(err) {
                assert.isNull(err);
              });
        });
    done();
  });

});