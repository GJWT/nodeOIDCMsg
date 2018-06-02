var expect = require('chai').expect;
var assert = require('chai').assert;
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');

describe('iat', function() {

  it('should work with a exp calculated based on numeric iat', function(done) {
    var dateNow = Math.floor(Date.now() / 1000);
    var iat = dateNow - 30;
    var expiresInVal = 50;
    var basicIdToken =
        new BasicIdToken({iss: 'issuer', sub: 'subject', iat: iat, jti: 'jti'});
    basicIdToken.addOptionalClaims({'aud': 'audience'});
    basicIdToken.toJWT('shhhh', {expiresIn: expiresInVal})
        .then(function(signedJWT) {
          var verificationClaims = {
            'iss': 'issuer',
            'sub': 'subject',
            'aud': 'audience',
            'maxAge': '1d',
            'jti': 'jti'
          };
          basicIdToken
              .fromJWT(
                  signedJWT, 'shhhh', verificationClaims,
                  {algorithms: ['HS256']})
              .then(function(decodedPayload) {
                expect(decodedPayload.exp)
                    .to.be.closeTo(iat + expiresInVal, 0.2);
                assert.isNotNull(decodedPayload);
              })
              .catch(function(err) {
                assert.isNull(err);
              });
        });
    done();
  });

  it('should throw if nbf or exp value does not match clock tolerance',
     function(done) {
       var clockTimestamp = 1000000000;

       var basicIdToken = new BasicIdToken(
           {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
       basicIdToken.addOptionalClaims({
         'aud': 'audience',
         'nbf': clockTimestamp + 2,
         'exp': clockTimestamp + 3
       });
       basicIdToken.setNoneAlgorithm(true);
       basicIdToken.toJWT('shhhh').then(function(signedJWT) {
         basicIdToken
             .fromJWT(
                 signedJWT, 'shhhh', {
                   'iss': 'issuer',
                   'sub': 'subject',
                   'aud': 'audience',
                   'maxAge': '1d',
                   'clockTolerance': 0.001,
                   'jti': 'jti'
                 },
                 {'clockTimestamp': clockTimestamp})
             .catch(function(err) {
               assert.isNotNull(err);
             });
       });
       done();
     });

  it('should check if iat does not match the max age value provided',
     function(done) {
       var clockTimestamp = 1000000000;

       var basicIdToken = new BasicIdToken(
           {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
       basicIdToken.addOptionalClaims({
         'aud': 'audience',
         'nbf': clockTimestamp + 2,
         'exp': clockTimestamp + 3
       });
       basicIdToken.setNoneAlgorithm(true);
       basicIdToken.toJWT('shhhh').then(function(signedJWT) {
       basicIdToken
                  .fromJWT(
                      signedJWT, 'shhhh', {
                        'iss': 'issuer',
                        'sub': 'subject',
                        'aud': 'audience',
                        'maxAge': '6d',
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

  it('should throw if clock Tolerance is not provided', function(done) {
    var clockTimestamp = 1000000000;

    var basicIdToken = new BasicIdToken(
        {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
    basicIdToken.addOptionalClaims({
      'aud': 'audience',
      'nbf': clockTimestamp + 2,
      'exp': clockTimestamp + 3
    });
    basicIdToken.setNoneAlgorithm(true);
    basicIdToken.toJWT('shhhh').then(function(signedJWT) {
      basicIdToken
          .fromJWT(
              signedJWT, 'shhhh', {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '1d',
                'jti': 'jti'
              },
              {'clockTimestamp': clockTimestamp})
          .then(function() {})
          .catch(function(err) {
            assert.isNotNull(err);
          });
    });
    done();
  });

  it('should throw if iat does not match the max age value provided',
     function(done) {
       var clockTimestamp = 1000000000;

       var basicIdToken = new BasicIdToken(
           {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
       basicIdToken.addOptionalClaims({
         'aud': 'audience',
         'nbf': clockTimestamp + 2,
         'exp': clockTimestamp + 3
       });
       basicIdToken.setNoneAlgorithm(true);
       var signedJWT = basicIdToken.toJWT('shhhh');
       try{
          let decodedPayload = basicIdToken
           .fromJWT(
               signedJWT, 'shhhh', {
                 'iss': 'issuer',
                 'sub': 'subject',
                 'aud': 'audience',
                 'clockTolerance': 10,
                 'maxAge': '1d',
                 'jti': 'jti'
               },
               {'clockTimestamp': clockTimestamp})
        }catch(err) {
          assert.isNotNull(err);
        }
       done();
     });
});