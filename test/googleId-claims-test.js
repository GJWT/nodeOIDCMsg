var fs = require('fs');
var path = require('path');
var assert = require('chai').assert;
var GoogleIdToken = require('../src/oicMsg/tokenProfiles/googleIdToken');

function loadKey(filename) {
  return fs.readFileSync(path.join(__dirname, filename));
}

var algorithms = {
  RS256: {
    pub_key: loadKey('pub.pem'),
    priv_key: loadKey('priv.pem'),
    invalid_pub_key: loadKey('invalid_pub.pem')
  },
  ES256: {
    // openssl ecparam -name secp256r1 -genkey -param_enc explicit -out
    // ecdsa-private.pem
    priv_key: loadKey('ecdsa-private.pem'),
    // openssl ec -in ecdsa-private.pem -pubout -out ecdsa-public.pem
    pub_key: loadKey('ecdsa-public.pem'),
    invalid_pub_key: loadKey('ecdsa-public-invalid.pem')
  }
};

describe('Asymmetric Algorithms', function() {

  Object.keys(algorithms).forEach(function(algorithm) {
    describe(algorithm, function() {
      var clockTimestamp = 1000000000;

      describe(
          'when signing a token with a known non standard claim', function() {
            var googleIdToken = new GoogleIdToken({
              name: 'name',
              email: 'email@google.com',
              picture: '/pathToPic',
              iss: 'issuer',
              sub: 'subject',
              iat: clockTimestamp
            });
            googleIdToken.addOptionalClaims(
                {'aud': 'audience', 'exp': clockTimestamp + 3});
            googleIdToken.setNoneAlgorithm(true);

            it('should check known non standard claim', function(done) {
              googleIdToken.toJWT('shhhh').then(function(signedJWT) {
                googleIdToken
                    .fromJWT(
                        signedJWT, 'shhhh', {
                          'name': 'name',
                          'email': 'email@google.com',
                          'picture': '/pathToPic',
                          'iss': 'issuer',
                          'aud': 'audience',
                          'maxAge': '1d',
                          'clockTolerance': 10,
                          'sub': 'subject'
                        },
                        {'clockTimestamp': clockTimestamp})
                    .then(function(decodedPayload) {
                      assert.isNotNull(decodedPayload);
                    })
                    .catch(function(err) {
                      assert.isNull(err);
                    });
              });
              done();
            });

            it('should throw when invalid known non standard claim',
               function(done) {
                 googleIdToken.toJWT('shhhh')
                     .then(function(signedJWT) {
                       googleIdToken.fromJWT(
                           signedJWT, 'shhhh', {
                             'name': 'name',
                             'email': 'email@google.com',
                             'picture': '/pathToPic',
                             'iss': 'issuer',
                             'aud': 'wrong-audience',
                             'maxAge': '1d',
                             'clockTolerance': 10,
                             'sub': 'subject'
                           },
                           {'clockTimestamp': clockTimestamp});
                     })
                     .catch(function(err) {
                       assert.isNotNull(err);
                     });
                 done();
               });
          });
    });

    describe('when signing a token without standard claim', function() {
      it('should throw error and require standard claim', function(done) {
        try {
          var clockTimestamp = 1000000000;          
          var googleIdToken = new GoogleIdToken({
            name: 'name',
            email: 'email@google.com',
            picture: '/pathToPic',
            iss: 'issuer',
            sub: 'subject'
          });
          googleIdToken.addOptionalClaims(
              {'aud': 'audience', 'exp': clockTimestamp + 3});
          googleIdToken.setNoneAlgorithm(true);
          googleIdToken.toJWT('shhhh');
        } catch (err) {
          assert.isNotNull(err);
          assert.instanceOf(err, Error);
        }
        done();
      });
    });

    describe('when adding claims to token profile', function() {
      var clockTimestamp = 1000000000;

      var googleIdToken = new GoogleIdToken({
        name: 'name',
        email: 'email@google.com',
        picture: '/pathToPic',
        iss: 'issuer',
        sub: 'subject',
        iat: clockTimestamp
      });
      googleIdToken.addOptionalClaims(
          {'aud': 'audience', 'exp': clockTimestamp + 3});
      googleIdToken.setNoneAlgorithm(true);

      it('should be able to access all standard claims', function(done) {
        try {
          var standardClaims = googleIdToken.getRequiredClaims();
          assert.deepEqual(standardClaims, {
            'name': 'name',
            'email': 'email@google.com',
            'picture': '/pathToPic',
            'iss': 'issuer',
            'sub': 'subject',
            'iat': clockTimestamp
          });
        } catch (err) {
          assert.isNull(err);
        }
        done();
      });

      it('should be able to access non standard claims separately',
         function(done) {
           try {
             var nonStandardClaims = googleIdToken.getOptionalClaims();
             assert.deepEqual(
                 nonStandardClaims,
                 {'aud': 'audience', 'exp': clockTimestamp + 3});
           } catch (err) {
             assert.isNull(err);
           }
           done();
         });
    });

    describe('when signing a token with standard claim', function() {
      var clockTimestamp = 1000000000;
      var googleIdToken = new GoogleIdToken({
        name: 'name',
        email: 'email@google.com',
        picture: '/pathToPic',
        iss: 'issuer',
        sub: 'subject',
        iat: clockTimestamp
      });
      googleIdToken.addOptionalClaims({'aud': 'audience'});
      googleIdToken.setNoneAlgorithm(true);

      it('should check standard claim', function(done) {
        googleIdToken.toJWT('shhhh').then(function(signedJWT) {
          googleIdToken
              .fromJWT(
                  signedJWT, 'shhhh', {
                    'name': 'name',
                    'email': 'email@google.com',
                    'picture': '/pathToPic',
                    'iss': 'issuer',
                    'sub': 'subject',
                    'maxAge': '1d',
                    'aud': 'audience'
                  },
                  {'clockTimestamp': clockTimestamp})
              .then(function(decodedPayload) {
                assert.isNotNull(decodedPayload);
              })
              .catch(function(err) {
                assert.isNull(err);
              });
        });
        done();
      });


      it('should throw when invalid standard claim', function(done) {
        googleIdToken.toJWT('shhhh').then(function(signedJWT) {
          googleIdToken
              .fromJWT(
                  signedJWT, 'shhhh', {
                    'name': 'name',
                    'email': 'email@google.com',
                    'picture': '/pathToPic',
                    'iss': 'wrong-issuer',
                    'sub': 'subject',
                    'maxAge': '1d',
                    'aud': 'audience'
                  },
                  {'clockTimestamp': clockTimestamp})
              .catch(function(err) {
                assert.isNotNull(err);
                assert.equal(err.name, 'JsonWebTokenError');
              });
        });
        done();
      });
    });
  });
});