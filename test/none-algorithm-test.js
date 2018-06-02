var assert = require('chai').assert;
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

describe('Asymmetric Algorithms', function() {

  describe('when signing a basic id token with none algorithm', function() {
    var clockTimestamp = 1000000000;

    var basicIdToken = new BasicIdToken({
      'iss': 'issuer',
      'sub': 'subject',
      'iat': clockTimestamp,
      'jti': 'jti'
    });
    basicIdToken.setNoneAlgorithm(true);

    it('should check if explicitly set', function(done) {
      basicIdToken.toJWT('shhhh', {algorithm: 'none'})
          .then(function(signedJWT) {
            try{
            let decodedPayload = basicIdToken
                .fromJWT(
                    signedJWT, 'shhhh', {
                      'iss': 'issuer',
                      'sub': 'subject',
                      'maxAge': '1d',
                      'clockTolerance': 10,
                      'jti': 'jti'
                    },
                    {}, {algorithms: ['none']});
                  }catch(err){
                  assert.isNotNull(err);
                };
            done();
          });
    });

    describe('when signing a token with none algorithm', function() {
      it('should throw if none algorithm not set by choice', function(done) {
        try {
          basicIdToken = new BasicIdToken({
            'iss': 'issuer',
            'sub': 'subject',
            'iat': clockTimestamp,
            'jti': 'jti'
          });
          basicIdToken.toJWT('shhhh', {algorithm: 'none'});
        } catch (err) {
          assert.isNotNull(err);
        }
        done();
      });
    });
  });
});