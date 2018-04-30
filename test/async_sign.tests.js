var expect = require('chai').expect;
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');
var assert = require('chai').assert;

describe('signing a token asynchronously', function() {
  var clockTimestamp = 1000000000;

  describe('when signing a token', function() {

    it('should return the same result as singing synchronously',
       function(done) {
         var secret = 'shhhh';
         var basicIdToken = new BasicIdToken(
             {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
         basicIdToken.addOptionalClaims({
           'foo': 'bar',
           'aud': 'audience',
           'nbf': clockTimestamp + 2,
           'exp': 1
         });
         basicIdToken.setNoneAlgorithm(true);
         basicIdToken.toJWT(secret, {algorithm: 'HS256'})
             .then(function(asyncToken) {
               var basicIdToken2 = new BasicIdToken({
                 iss: 'issuer',
                 sub: 'subject',
                 iat: clockTimestamp,
                 jti: 'jti'
               });
               basicIdToken2.addOptionalClaims({
                 'foo': 'bar',
                 'aud': 'audience',
                 'nbf': clockTimestamp + 2,
                 'exp': 1
               });
               basicIdToken2.setNoneAlgorithm(true);
               basicIdToken2.toJWT(secret, {algorithm: 'HS256'})
                                   .then(function(syncToken) {
                                     expect(asyncToken).to.equal(syncToken);
                                   })
                                   .catch(function(err) {
                                     assert.isNull(err);
                                   });

               expect(asyncToken).to.be.a('string');
               expect(asyncToken.split('.')).to.have.length(3);
             })
             .catch(function(err) {
               assert.isNull(err);
             });
         done();
       });

    it('should work with empty options', function(done) {
      var secret = 'secret';
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
      basicIdToken.addOptionalClaims(
          {'abc': 1, 'aud': 'audience', 'nbf': clockTimestamp + 2, 'exp': 1});
      basicIdToken.setNoneAlgorithm(true);
      basicIdToken.toJWT(secret, {})
          .catch(function(err) {
            expect(err).to.be.null();
          });
      done();
    });

    it('should work without options object at all', function(done) {
      var secret = 'secret';
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
      basicIdToken.addOptionalClaims(
          {'abc': 1, 'aud': 'audience', 'nbf': clockTimestamp + 2, 'exp': 1});
      basicIdToken.setNoneAlgorithm(true);
      basicIdToken.toJWT(secret)
          .catch(function(err) {
            expect(err).to.be.null();
          });
      done();
    });

    it('should work with none algorithm where secret is set', function(done) {
      var secret = 'secret';
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
      basicIdToken.addOptionalClaims(
          {foo: 'bar', 'aud': 'audience', 'nbf': clockTimestamp + 2, 'exp': 1});
      basicIdToken.setNoneAlgorithm(true);
      basicIdToken.toJWT(secret, {algorithm: 'none'})
          .then(function(token) {
            expect(token).to.be.a('string');
            expect(token.split('.')).to.have.length(3);
          })
          .catch(function(err) {
            expect(err).to.be.null();
          });
      done();
    });

    // Known bug: https://github.com/brianloveswords/node-jws/issues/62
    // If you need this use case, you need to go for the non-callback-ish code
    // style.
    it.skip(
        'should work with none algorithm where secret is falsy',
        function(done) {
          var basicIdToken = new BasicIdToken(
              {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
          basicIdToken.addOptionalClaims({
            foo: 'bar',
            'aud': 'audience',
            'nbf': clockTimestamp + 2,
            'exp': 1
          });
          basicIdToken.setNoneAlgorithm(true);
          basicIdToken.toJWT(undefined, {algorithm: 'none'})
              .then(function(token) {
                expect(token).to.be.a('string');
                expect(token.split('.')).to.have.length(3);
              })
              .catch(function(err) {
                expect(err).to.be.null();
              });
          done();
        });

    it('should return error when secret is not a cert for RS256',
       function(done) {
         // this throw an error because the secret is not a cert and RS256
         // requires a cert.

         var secret = 'secret';
         var basicIdToken = new BasicIdToken(
             {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
         basicIdToken.addOptionalClaims({
           foo: 'bar',
           'aud': 'audience',
           'nbf': clockTimestamp + 2,
           'exp': 1
         });
         basicIdToken.setNoneAlgorithm(true);
         basicIdToken.toJWT(secret, {algorithm: 'RS256'})
             .then(function(token) {
               expect(token).to.be.a('string');
               expect(token.split('.')).to.have.length(3);
             })
             .catch(function(err) {
               expect(err).to.be.ok();
             });
         done();
       });

    it('should return error on wrong arguments', function(done) {
      // this throw an error because the secret is not a cert and RS256 requires
      // a cert.  this throw an error because the secret is not a cert and RS256
      // requires a cert.
      try {
        var secret = 'secret';
        var basicIdToken = new BasicIdToken(
            {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
        basicIdToken.addOptionalClaims({
          'foo': 'bar',
          'aud': 'audience',
          'nbf': clockTimestamp + 2,
          'exp': 1
        });
        basicIdToken.setNoneAlgorithm(true);
        basicIdToken.toJWT(secret, {notBefore: {}});
      } catch (err) {
        expect(err).to.be.ok();
      }
      done();
    });

    it('should return error on wrong arguments (2)', function(done) {
      var secret = 'secret';
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
      basicIdToken.addOptionalClaims(
          {foo: 'bar', 'aud': 'audience', 'nbf': clockTimestamp + 2, 'exp': 1});
      basicIdToken.setNoneAlgorithm(true);
      basicIdToken.toJWT(secret, {noTimestamp: true})
          .catch(function(err) {
            expect(err).to.be.ok();
            expect(err).to.be.instanceof (Error);
          });
      done();
    });

    it('should not stringify the payload', function(done) {
      var secret = 'secret';
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: clockTimestamp, jti: 'jti'});
      basicIdToken.addOptionalClaims({
        'payload': 'string',
        'aud': 'audience',
        'nbf': clockTimestamp + 2,
        'exp': clockTimestamp + 3
      });
      basicIdToken.setNoneAlgorithm(true);
      basicIdToken.toJWT(secret, {}).then(function(token) {
        basicIdToken
            .fromJWT(
                token, secret, {
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '1d',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp})
            .then(function(result) {
              expect(result.payload).to.equal('string');
            })
            .catch(function(err) {
              expect(err).to.be.null();
            });
      });
      done();
    });

    describe('secret must have a value', function() {
      [undefined, '', 0].forEach(function(secret) {
        it('should return an error if the secret is falsy and algorithm is not set to none: ' +
               (typeof secret === 'string' ? '(empty string)' : secret),
           function(done) {
             // This is needed since jws will not answer for falsy secrets
             var basicIdToken = new BasicIdToken({
               iss: 'issuer',
               sub: 'subject',
               iat: clockTimestamp,
               jti: 'jti'
             });
             basicIdToken.addOptionalClaims({
               'aud': 'audience',
               'nbf': clockTimestamp + 2,
               'exp': clockTimestamp + 3
             });
             basicIdToken.setNoneAlgorithm(true);
             basicIdToken.toJWT('secret', {})
                 .catch(function(err) {
                   expect(err).to.be.exist();
                   expect(err.message)
                       .to.equal('secretOrPrivateKey must have a value');
                 });
             done();
           });
      });
    });
  });
});