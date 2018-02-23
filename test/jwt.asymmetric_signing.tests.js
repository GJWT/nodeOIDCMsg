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
      var pub = algorithms[algorithm].pub_key;
      var priv = algorithms[algorithm].priv_key;

      // "invalid" means it is not the public key for the loaded "priv" key
      var invalid_pub = algorithms[algorithm].invalid_pub_key;

      describe('when signing a token', function() {
        // var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm });

        var clockTimestamp = 1000000000;

        var basicIdToken =
            new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
        basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT(priv, {algorithm: algorithm});

        it('should be syntactically valid', function() {
          expect(token).to.be.a('string');
          expect(token.split('.')).to.have.length(3);
        });

        context('asynchronous', function() {
          it('should validate with public key', function(done) {

            var decoded = basicIdToken.fromJWT(
                token, pub, {
                  'foo': 'bar',
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '3s',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp});
            assert.ok(decoded.iss);
            assert.equal('issuer', decoded.iss);
            done();

          });

          it('should throw with invalid public key', function(done) {
            try {
              var decoded = basicIdToken.fromJWT(
                  token, invalid_pub, {
                    'foo': 'bar',
                    'iss': 'issuer',
                    'sub': 'subject',
                    'aud': 'audience',
                    'maxAge': '3s',
                    'clockTolerance': 10,
                    'jti': 'jti'
                  },
                  {'clockTimestamp': clockTimestamp});
            } catch (err) {
              assert.isUndefined(decoded);
              assert.isNotNull(err);
              done();
            }
          });
        });

        context('synchronous', function() {
          it('should validate with public key', function(done) {
            var decoded = basicIdToken.fromJWT(
                token, pub, {
                  'foo': 'bar',
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '3s',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp});
            assert.ok(decoded.iss);
            assert.equal('issuer', decoded.iss);
            done();
          });

          it('should throw with invalid public key synchronous',
             function(done) {
               try {
                 var decoded = basicIdToken.fromJWT(
                     token, invalid_pub, {
                       'foo': 'bar',
                       'iss': 'issuer',
                       'sub': 'subject',
                       'aud': 'audience',
                       'maxAge': '3s',
                       'clockTolerance': 10,
                       'jti': 'jti'
                     },
                     {'clockTimestamp': clockTimestamp});
               } catch (err) {
                 assert.isUndefined(decoded);
                 assert.isNotNull(err);
                 done();
               }
             });
        });

      });


      describe('when signing a token with expiration', function() {
        var clockTimestamp = 1000000000;

        var basicIdToken =
            new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
        basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
        basicIdToken.setNoneAlgorithm(true);
        var token =
            basicIdToken.toJWT(priv, {expiresIn: '10m', algorithm: algorithm});

        it('should be valid expiration', function(done) {
          try {
            var decoded = basicIdToken.fromJWT(
                token, pub, {
                  'foo': 'bar',
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '3s',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp});
            assert.isNotNull(decoded);
          } catch (err) {
            assert.isNull(err);
          }
          done();

        });

        it('should be invalid', function(done) {

          var basicIdToken =
              new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
          basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
          basicIdToken.setNoneAlgorithm(true);
          var token = basicIdToken.toJWT(
              priv, {expiresIn: -1 * ms('10m'), algorithm: algorithm});


          try {
            var decoded = basicIdToken.fromJWT(
                token, pub, {
                  'foo': 'bar',
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '3s',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp});
          } catch (err) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'TokenExpiredError');
            assert.instanceOf(err.expiredAt, Date);
            done();
          }

        });

        it('should NOT be invalid', function(done) {

          var basicIdToken =
              new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
          basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
          basicIdToken.setNoneAlgorithm(true);
          var token = basicIdToken.toJWT(
              priv, {expiresIn: -1 * ms('10m'), algorithm: algorithm});

          var decoded = basicIdToken.fromJWT(
              token, pub, {
                'foo': 'bar',
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '3s',
                'clockTolerance': 10,
                'jti': 'jti'
              },
              {'clockTimestamp': clockTimestamp, ignoreExpiration: true});
          assert.ok(decoded.iss);
          assert.equal('issuer', decoded.iss);
          done();
        });
      });


      describe('when signing a token with not before', function() {
        // var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm,
        // notBefore: -10 * 3600 });
        var clockTimestamp = 1521783267;

        var basicIdToken =
            new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
        basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT(
            'shhh', {notBefore: -10 * 3600, algorithm: 'HS256'});


        it('should be valid expiration', function(done) {
          /*jwt.verify(token, pub, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });*/

          try {
            var decoded = basicIdToken.fromJWT(
                token, 'shhh', {
                  'foo': 'bar',
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '3s',
                  'clockTolerance': 500,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp});
          } catch (err) {
            assert.isNotNull(decoded);
            assert.isNull(err);
          }
          done();

        });

        it('should be invalid', function(done) {
          // not active token
          // token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm,
          // notBefore: '10m' });
          var clockTimestamp = 1511783267;

          var basicIdToken =
              new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
          basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
          basicIdToken.setNoneAlgorithm(true);
          var token = basicIdToken.toJWT(
              priv, {notBefore: '10m', algorithm: algorithm});

          try {
            var decoded = basicIdToken.fromJWT(
                token, pub, {
                  'foo': 'bar',
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '3s',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp});
          } catch (err) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'NotBeforeError');
            assert.instanceOf(err.date, Date);
            done();
          }

          /*
          jwt.verify(token, pub, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'NotBeforeError');
            assert.instanceOf(err.date, Date);
            assert.instanceOf(err, jwt.NotBeforeError);
            done();
          });*/
        });


        it('should be valid when date are equals', function(done) {
          var clockTimestamp = 1520000000;

          // token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm,
          // notBefore: 0 });

          var basicIdToken =
              new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
          basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
          basicIdToken.setNoneAlgorithm(true);
          var token =
              basicIdToken.toJWT('shh', {notBefore: 0, algorithm: 'HS256'});

          try {
            var decoded = basicIdToken.fromJWT(
                token, 'shh', {
                  'foo': 'bar',
                  'iss': 'issuer',
                  'sub': 'subject',
                  'aud': 'audience',
                  'maxAge': '3s',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp});
          } catch (err) {
            assert.isNull(err);
            assert.isNotNull(decoded);
          }
          done();

        });

        it('should NOT be invalid', function(done) {
          // not active token
          // token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm,
          // notBefore: '10m' });

          var basicIdToken =
              new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
          basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
          basicIdToken.setNoneAlgorithm(true);
          var token =
              basicIdToken.toJWT(priv, {notBefore: 0, algorithm: algorithm});

          /*
          jwt.verify(token, pub, { ignoreNotBefore: true }, function (err,
          decoded) { assert.ok(decoded.foo); assert.equal('bar', decoded.foo);
            done();
          });*/

          var decoded = basicIdToken.fromJWT(
              token, pub, {
                'foo': 'bar',
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '3s',
                'clockTolerance': 10,
                'jti': 'jti'
              },
              {'clockTimestamp': clockTimestamp, ignoreNotBefore: true});
          assert.ok(decoded.iss);
          assert.equal('issuer', decoded.iss);
          done();
        });
      });


      describe('when signing a token without audience', function() {
        var clockTimestamp = 1511783267;

        var basicIdToken =
            new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
        basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'urn:foo'});
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT('shh', {algorithm: 'HS256'});

        it('should check audience using RegExp', function(done) {

          try {
            var decoded = basicIdToken.fromJWT(
                token, 'shh', {
                  'foo': 'bar',
                  'aud': /urn:f[o]{2}/,
                  'iss': 'issuer',
                  'sub': 'subject',
                  'maxAge': '3s',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp});
          } catch (err) {
            assert.isNull(err);
          }
          done();


        });

        it('should throw invalid audience using RegExp', function(done) {

          try {
            var decoded = basicIdToken.fromJWT(
                token, 'shh', {
                  'foo': 'bar',
                  'aud': /urn:wrong/,
                  'iss': 'issuer',
                  'sub': 'subject',
                  'maxAge': '3s',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp});
          } catch (err) {
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            done();
          }

        });
      });



      describe('when signing a token with jwt id', function() {

        var clockTimestamp = 1511783267;

        var basicIdToken =
            new BasicIdToken('issuer', 'subject', clockTimestamp, 'jwtid');
        basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT('shh', {algorithm: 'HS256'});

        // var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm,
        // jwtid: 'jwtid' });

        it('should check jwt id', function(done) {
          /*jwt.verify(token, pub, { jwtid: 'jwtid' }, function (err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });*/

          try {
            var decoded = basicIdToken.fromJWT(
                token, 'shh', {
                  'foo': 'bar',
                  'aud': 'audience',
                  'iss': 'issuer',
                  'sub': 'subject',
                  'maxAge': '3s',
                  'clockTolerance': 10,
                  'jti': 'jwtid'
                },
                {'clockTimestamp': clockTimestamp, jwtid: 'jwtid'});
          } catch (err) {
            assert.isNotNull(decoded);
            assert.isNull(err);
          }
          done();
        });

        it('should throw when invalid jwt id', function(done) {
          try {
            var decoded = basicIdToken.fromJWT(
                token, pub, {
                  'foo': 'bar',
                  'aud': 'audience',
                  'iss': 'issuer',
                  'sub': 'subject',
                  'maxAge': '3s',
                  'clockTolerance': 10,
                  'jti': 'jti'
                },
                {'clockTimestamp': clockTimestamp, jwtid: 'wrongJwtid'});
          } catch (err) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            done();
          }

        });
      });

      /*
      describe('when signing a token without jwt id', function () {
        var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm });

        it('should check jwt id', function (done) {
          jwt.verify(token, pub, { jwtid: 'jwtid' }, function (err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            assert.instanceOf(err, jwt.JsonWebTokenError);
            done();
          });
        });
      });*/

      describe('when verifying a malformed token', function() {

        var clockTimestamp = 1511783267;

        var basicIdToken =
            new BasicIdToken('issuer', 'subject', clockTimestamp, 'jwtid');


        it('should throw', function(done) {
          try {
            var decoded = basicIdToken.fromJWT(
                'fruit.fruit.fruit', pub, {
                  'foo': 'bar',
                  'aud': 'audience',
                  'iss': 'issuer',
                  'sub': 'subject',
                  'maxAge': '3s',
                  'clockTolerance': 10,
                  'jti': 'jwtid'
                },
                {'clockTimestamp': clockTimestamp, jwtid: 'jwtid'});
          } catch (err) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            done();
          }
        });
      });


      describe('when decoding a jwt token with additional parts', function() {

        var clockTimestamp = 1511783267;

        var basicIdToken =
            new BasicIdToken('issuer', 'subject', clockTimestamp, 'jwtid');
        basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT(priv, {algorithm: algorithm});
        // var token = jwt.sign({ foo: 'bar' }, priv, { algorithm: algorithm });

        it('should throw', function(done) {
          try {
            var decoded = basicIdToken.fromJWT(
                token + '.foo', pub, {
                  'foo': 'bar',
                  'aud': 'audience',
                  'iss': 'issuer',
                  'sub': 'subject',
                  'maxAge': '3s',
                  'clockTolerance': 10,
                  'jti': 'jwtid'
                },
                {'clockTimestamp': clockTimestamp, jwtid: 'jwtid'});
          } catch (err) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            done();
          }
        });
      });



      describe('when decoding a invalid jwt token', function() {
        var clockTimestamp = 1511783267;

        var basicIdToken =
            new BasicIdToken('issuer', 'subject', clockTimestamp, 'jwtid');

        it('should return null', function(done) {
          try {
            var decoded = basicIdToken.fromJWT(
                'whatever.token', pub, {
                  'foo': 'bar',
                  'aud': 'audience',
                  'iss': 'issuer',
                  'sub': 'subject',
                  'maxAge': '3s',
                  'clockTolerance': 10,
                  'jti': 'jwtid'
                },
                {'clockTimestamp': clockTimestamp, jwtid: 'jwtid'});
          } catch (err) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            assert.equal(err.name, 'JsonWebTokenError');
            done();
          }
        });
      });
    });
  });
});