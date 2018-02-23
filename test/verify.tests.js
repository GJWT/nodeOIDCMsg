var jwt = require('../index');
var jws = require('../src/oicMsg/jose/jws');
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');
var RefreshToken = require('../src/oicMsg/tokenProfiles/refreshToken');
var fs = require('fs');
var path = require('path');
var sinon = require('sinon');

var assert = require('chai').assert;

describe('verify', function() {
  var pub = fs.readFileSync(path.join(__dirname, 'pub.pem'));
  var priv = fs.readFileSync(path.join(__dirname, 'priv.pem'));

  it('should first assume JSON claim set', function(done) {
    var header = {alg: 'RS256'};
    var payload = {iat: Math.floor(Date.now() / 1000)};

    var secret = 'secret';
    var basicIdToken = new BasicIdToken(
        'issuer', 'subject', Math.floor(Date.now() / 1000), 'jti');
    basicIdToken.addOptionalClaims({
      'payload': 'string',
      'aud': 'audience',
      'nbf': Math.floor(Date.now() / 1000) + 2,
      'exp': Math.floor(Date.now() / 1000) + 3
    });
    basicIdToken.setNoneAlgorithm(true);
    var token = basicIdToken.toJWT(priv, {header: header, encoding: 'utf8'});

    try {
      var result = basicIdToken.fromJWT(
          token, pub, {
            'iss': 'issuer',
            'sub': 'subject',
            'aud': 'audience',
            'maxAge': '1d',
            'clockTolerance': 10,
            'jti': 'jti'
          },
          {'clockTimestamp': Math.floor(Date.now() / 1000), typ: 'JWT'});
    } catch (err) {
      assert.isNull(err);
    }
    done();

  });


  it('should be able to validate unsigned token', function(done) {
    var header = {alg: 'none'};
    var payload = {iat: Math.floor(Date.now() / 1000)};

    var secret = 'secret';
    var basicIdToken = new BasicIdToken(
        'issuer', 'subject', Math.floor(Date.now() / 1000), 'jti');
    basicIdToken.addOptionalClaims({
      'payload': 'string',
      'aud': 'audience',
      'nbf': Math.floor(Date.now() / 1000) + 2,
      'exp': Math.floor(Date.now() / 1000) + 3
    });
    basicIdToken.setNoneAlgorithm(true);
    var token = basicIdToken.toJWT(priv, {header: header, encoding: 'utf8'});

    try {
      var result = basicIdToken.fromJWT(
          token, null, {
            'iss': 'issuer',
            'sub': 'subject',
            'aud': 'audience',
            'maxAge': '1d',
            'clockTolerance': 10,
            'jti': 'jti'
          },
          {'clockTimestamp': Math.floor(Date.now() / 1000), typ: 'JWT'});
    } catch (err) {
      assert.isNull(err);
    }
    done();

  });

  it('should not mutate options', function(done) {
    var header = {alg: 'none'};

    var payload = {iat: Math.floor(Date.now() / 1000)};

    var options = {typ: 'JWT'};

    var secret = 'secret';
    var basicIdToken = new BasicIdToken(
        'issuer', 'subject', Math.floor(Date.now() / 1000), 'jti');
    basicIdToken.addOptionalClaims({
      'payload': 'string',
      'aud': 'audience',
      'nbf': Math.floor(Date.now() / 1000) + 2,
      'exp': Math.floor(Date.now() / 1000) + 3
    });
    basicIdToken.setNoneAlgorithm(true);
    var token = basicIdToken.toJWT(priv, {header: header, encoding: 'utf8'});

    try {
      var result = basicIdToken.fromJWT(
          token, null, {
            'iss': 'issuer',
            'sub': 'subject',
            'aud': 'audience',
            'maxAge': '1d',
            'clockTolerance': 10,
            'jti': 'jti'
          },
          {'clockTimestamp': Math.floor(Date.now() / 1000), typ: 'JWT'});
    } catch (err) {
      assert.isNull(err);
      assert.deepEqual(Object.keys(options).length, 1);
    }
    done();
  });


  describe('expiration', function() {

    var key = 'key';

    var clock;
    afterEach(function() {
      try {
        clock.restore();
      } catch (e) {
      }
    });

    var secret = 'secret';
    var basicIdToken = new BasicIdToken('issuer', 'subject', 1437018582, 'jti');
    basicIdToken.addOptionalClaims(
        {'foo': 'bar', 'aud': 'audience', 'exp': 1437018592});
    basicIdToken.setNoneAlgorithm(true);
    var token = basicIdToken.toJWT(key);


    it('should error on expired token', function(done) {
      clock = sinon.useFakeTimers(1437018650000);  // iat + 58s, exp + 48s
      var options = {algorithms: ['HS256']};
      try {
        var result = basicIdToken.fromJWT(
            token, key, {
              'iss': 'issuer',
              'sub': 'subject',
              'aud': 'audience',
              'maxAge': '1d',
              'clockTolerance': 10,
              'jti': 'jti'
            },
            options);
      } catch (err) {
        assert.equal(err.name, 'TokenExpiredError');
        assert.equal(err.message, 'jwt expired');
        assert.equal(err.expiredAt.constructor.name, 'Date');
        assert.equal(Number(err.expiredAt), 1437018592000);
        assert.isUndefined(result);
        done();
      }
    });

    it('should not error on expired token within clockTolerance interval',
       function(done) {
         clock = sinon.useFakeTimers(1437018594000);  // iat + 12s, exp + 2s
         var options = {algorithms: ['HS256'], clockTolerance: 5}

         try {
           var result = basicIdToken.fromJWT(
               token, key, {
                 'iss': 'issuer',
                 'sub': 'subject',
                 'aud': 'audience',
                 'maxAge': '1d',
                 'clockTolerance': 10,
                 'jti': 'jti'
               },
               options);
         } catch (err) {
           assert.isNull(err);
           assert.equal(result.foo, 'bar');
         }
         done();

       });

    it('should not error if within maxAge timespan', function(done) {
      clock = sinon.useFakeTimers(1437018587500);  // iat + 5.5s, exp - 4.5s
      var options = {algorithms: ['HS256'], maxAge: '6s'};

      try {
        var result = basicIdToken.fromJWT(
            token, key, {
              'iss': 'issuer',
              'sub': 'subject',
              'aud': 'audience',
              'maxAge': '6s',
              'clockTolerance': 10,
              'jti': 'jti'
            },
            options);
      } catch (err) {
        assert.isNull(err);
        assert.equal(result.foo, 'bar');
      }
      done();
    });


    describe('option: maxAge', function() {

      var options = {algorithms: ['HS256'], clockTimestamp: 1437018587000};
      var key = 'secret';
      var basicIdToken =
          new BasicIdToken('issuer', 'subject', 1437018587000 - 5, 'jti');
      basicIdToken.addOptionalClaims(
          {'foo': 'bar', 'aud': 'audience', 'exp': 1437018587000 + 5});
      basicIdToken.setNoneAlgorithm(true);
      var token = basicIdToken.toJWT(key);

      [String('3s'), '3s', 3].forEach(function(maxAge) {
        it(`should error for claims issued before a certain timespan (${
                                                                        typeof
                                                                            maxAge
                                                                      } type)`,
           function(done) {
             clock = sinon.useFakeTimers(1437018587000);  // iat + 5s, exp - 5s

             try {
               var result = basicIdToken.fromJWT(
                   token, key, {
                     'iss': 'issuer',
                     'sub': 'subject',
                     'aud': 'audience',
                     'maxAge': maxAge,
                     'clockTolerance': 0.001,
                     'jti': 'jti'
                   },
                   options);
             } catch (err) {
               assert.equal(err.name, 'TokenExpiredError');
               assert.equal(err.message, 'maxAge exceeded');
               assert.equal(err.expiredAt.constructor.name, 'Date');
               assert.equal(Number(err.expiredAt), 1437018586998000);
               assert.isUndefined(result);
               done();
             }

           });
      });

      [String('5s'), '5s', 5].forEach(function(maxAge) {
        it(`should not error for claims issued before a certain timespan but still inside clockTolerance timespan (${
                                                                                                                     typeof
                                                                                                                         maxAge
                                                                                                                   } type)`,
           function(done) {
             clock =
                 sinon.useFakeTimers(1437018587500);  // iat + 5.5s, exp - 4.5s
             var options = {
               algorithms: ['HS256'],
               maxAge: maxAge,
               clockTolerance: 1
             };


             try {
               var result = basicIdToken.fromJWT(
                   token, key, {
                     'iss': 'issuer',
                     'sub': 'subject',
                     'aud': 'audience',
                     'maxAge': maxAge,
                     'clockTolerance': 0.001,
                     'jti': 'jti'
                   },
                   options);
             } catch (err) {
               assert.isNull(err);
               assert.equal(result.foo, 'bar');
             }
             done();
           });
      });

      [String('6s'), '6s', 6].forEach(function(maxAge) {
        it(`should not error if within maxAge timespan (${typeof maxAge} type)`,
           function(done) {
             clock =
                 sinon.useFakeTimers(1437018587500);  // iat + 5.5s, exp - 4.5s
             var options = {algorithms: ['HS256'], maxAge: maxAge};

             try {
               var result = basicIdToken.fromJWT(
                   token, key, {
                     'iss': 'issuer',
                     'sub': 'subject',
                     'aud': 'audience',
                     'maxAge': maxAge,
                     'clockTolerance': 0.001,
                     'jti': 'jti'
                   },
                   options);
             } catch (err) {
               assert.isNull(err);
               assert.equal(result.foo, 'bar');
             }
             done();
           });
      });

      [String('8s'), '8s', 8].forEach(function(maxAge) {
        it(`can be more restrictive than expiration (${typeof maxAge} type)`,
           function(done) {
             clock =
                 sinon.useFakeTimers(1437018591900);  // iat + 9.9s, exp - 0.1s
             var options = {algorithms: ['HS256'], maxAge: maxAge};

             try {
               var result = basicIdToken.fromJWT(
                   token, key, {
                     'iss': 'issuer',
                     'sub': 'subject',
                     'aud': 'audience',
                     'maxAge': maxAge,
                     'clockTolerance': 0.001,
                     'jti': 'jti'
                   },
                   options);
             } catch (err) {
               assert.equal(err.name, 'TokenExpiredError');
               assert.equal(err.message, 'maxAge exceeded');
               assert.equal(err.expiredAt.constructor.name, 'Date');
               assert.equal(Number(err.expiredAt), 1437018586998000);
               assert.isUndefined(result);
             }
             done();
           });
      });

      [String('12s'), '12s', 12].forEach(function(maxAge) {
        it(`cannot be more permissive than expiration (${typeof maxAge} type)`,
           function(done) {
             clock = sinon.useFakeTimers(1437018593000);  // iat + 11s, exp + 1s
             var options = {algorithms: ['HS256'], maxAge: '12s'};

             try {
               var result = basicIdToken.fromJWT(
                   token, key, {
                     'iss': 'issuer',
                     'sub': 'subject',
                     'aud': 'audience',
                     'maxAge': maxAge,
                     'clockTolerance': 0.001,
                     'jti': 'jti'
                   },
                   options);
             } catch (err) {
               assert.equal(err.name, 'TokenExpiredError');
               assert.equal(err.message, 'jwt expired');
               assert.equal(err.expiredAt.constructor.name, 'Date');
               assert.equal(Number(err.expiredAt), 1437018586998000);
               assert.isUndefined(result);
             }
             done();

           });
      });

      [new String('1s'), 'no-timespan-string'].forEach(function(maxAge) {
        it(`should error if maxAge is specified with a wrong string format/type (value: ${
                                                                                          maxAge
                                                                                        }, type: ${
                                                                                                   typeof
                                                                                                       maxAge
                                                                                                 })`,
           function(done) {
             clock = sinon.useFakeTimers(1437018587000);  // iat + 5s, exp - 5s
             var options = {algorithms: ['HS256'], maxAge: maxAge};

             try {
               var result = basicIdToken.fromJWT(
                   token, key, {
                     'iss': 'issuer',
                     'sub': 'subject',
                     'aud': 'audience',
                     'maxAge': maxAge,
                     'clockTolerance': 0.001,
                     'jti': 'jti'
                   },
                   options);
             } catch (err) {
               assert.equal(err.name, 'JsonWebTokenError');
               assert.equal(
                   err.message,
                   '"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60');
               assert.isUndefined(result);
             }
             done();
           });
      });

      it('should error if maxAge is specified but there is no iat claim',
         function(done) {
           var options = {algorithms: ['HS256'], maxAge: '1s'};

           try {
             var result = basicIdToken.fromJWT(
                 token, key, {
                   'iss': 'issuer',
                   'sub': 'subject',
                   'aud': 'audience',
                   'maxAge': '1s',
                   'clockTolerance': 0.001,
                   'jti': 'jti'
                 },
                 options);
           } catch (err) {
             assert.equal(err.name, 'JsonWebTokenError');
             assert.equal(err.message, 'iat required when maxAge is specified');
             assert.isUndefined(result);
           }
           done();
         });

    });


    describe('option: clockTimestamp', function() {
      var clockTimestamp = 1000000000;
      it('should verify unexpired token relative to user-provided clockTimestamp',
         function(done) {
           var key = 'secret';
           var basicIdToken =
               new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
           basicIdToken.addOptionalClaims(
               {'foo': 'bar', 'aud': 'audience', 'exp': clockTimestamp + 1});
           basicIdToken.setNoneAlgorithm(true);
           var token = basicIdToken.toJWT(key);

           try {
             var result = basicIdToken.fromJWT(
                 token, key, {
                   'iss': 'issuer',
                   'sub': 'subject',
                   'aud': 'audience',
                   'maxAge': '3s',
                   'clockTolerance': 0.001,
                   'jti': 'jti'
                 },
                 {clockTimestamp: clockTimestamp});
           } catch (err) {
             assert.equal(err.name, 'JsonWebTokenError');
             assert.equal(err.message, 'iat required when maxAge is specified');
             assert.isUndefined(result);
           }
           done();
         });
      it('should error on expired token relative to user-provided clockTimestamp',
         function(done) {
           var key = 'secret';
           var basicIdToken =
               new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
           basicIdToken.addOptionalClaims(
               {'foo': 'bar', 'aud': 'audience', 'exp': clockTimestamp + 1});
           basicIdToken.setNoneAlgorithm(true);
           var token = basicIdToken.toJWT(key);

           try {
             var result = basicIdToken.fromJWT(
                 token, key, {
                   'iss': 'issuer',
                   'sub': 'subject',
                   'aud': 'audience',
                   'maxAge': '3s',
                   'clockTolerance': 0.001,
                   'jti': 'jti'
                 },
                 {clockTimestamp: clockTimestamp + 1});
           } catch (err) {
             assert.equal(err.name, 'TokenExpiredError');
             assert.equal(err.message, 'jwt expired');
             assert.equal(err.expiredAt.constructor.name, 'Date');
             assert.equal(Number(err.expiredAt), (clockTimestamp + 1) * 1000);
             assert.isUndefined(result);
             done();
           }
           done();
         });


      it('should verify clockTimestamp is a number', function(done) {
        var key = 'secret';
        var basicIdToken =
            new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
        basicIdToken.addOptionalClaims(
            {'foo': 'bar', 'aud': 'audience', 'exp': clockTimestamp + 1});
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT(key);

        try {
          var result = basicIdToken.fromJWT(
              token, key, {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '3s',
                'clockTolerance': 0.001,
                'jti': 'jti'
              },
              {clockTimestamp: 'notANumber'});
        } catch (err) {
          assert.equal(err.name, 'JsonWebTokenError');
          assert.equal(err.message, 'clockTimestamp must be a number');
          assert.isUndefined(result);
          done();
        }
      });

      it('should verify valid token with nbf', function(done) {
        var key = 'secret';
        var basicIdToken =
            new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
        basicIdToken.addOptionalClaims({
          'foo': 'bar',
          'aud': 'audience',
          'exp': clockTimestamp + 2,
          'nbf': clockTimestamp + 1
        });
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT(key);

        try {
          var result = basicIdToken.fromJWT(
              token, key, {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '3s',
                'clockTolerance': 0.001,
                'jti': 'jti'
              },
              {clockTimestamp: clockTimestamp + 1});
        } catch (err) {
          assert.isNull(err);
        }
        done();

      });

      it('should error on token used before nbf', function(done) {
        var key = 'secret';
        var basicIdToken =
            new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
        basicIdToken.addOptionalClaims({
          'foo': 'bar',
          'aud': 'audience',
          'exp': clockTimestamp + 2,
          'nbf': clockTimestamp + 1
        });
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT(key);

        try {
          var result = basicIdToken.fromJWT(
              token, key, {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '3s',
                'clockTolerance': 10,
                'jti': 'jti'
              },
              {clockTimestamp: clockTimestamp});
        } catch (err) {
          assert.isNull(err);
        }
        done();

      });
    });

    describe('option: maxAge and clockTimestamp', function() {
      // { foo: 'bar', iat: 1437018582, exp: 1437018800 } exp = iat + 218s
      // var token =
      // 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmb28iOiJiYXIiLCJpYXQiOjE0MzcwMTg1ODIsImV4cCI6MTQzNzAxODgwMH0.AVOsNC7TiT-XVSpCpkwB1240izzCIJ33Lp07gjnXVpA';

      var key = 'secret';
      var basicIdToken =
          new BasicIdToken('issuer', 'subject', 1437018582, 'jti');
      basicIdToken.addOptionalClaims(
          {'foo': 'bar', 'aud': 'audience', 'exp': 1437018800});
      basicIdToken.setNoneAlgorithm(true);
      var token = basicIdToken.toJWT(key);

      it('should error for claims issued before a certain timespan',
         function(done) {
           var clockTimestamp = 1437018682;
           var options = {
             algorithms: ['HS256'],
             clockTimestamp: clockTimestamp,
             maxAge: '1m'
           };

           try {
             var result = basicIdToken.fromJWT(
                 token, key, {
                   'iss': 'issuer',
                   'sub': 'subject',
                   'aud': 'audience',
                   'maxAge': '1m',
                   'clockTolerance': 10,
                   'jti': 'jti'
                 },
                 options);
           } catch (err) {
             assert.equal(err.name, 'TokenExpiredError');
             assert.equal(err.message, 'maxAge exceeded');
             assert.equal(err.expiredAt.constructor.name, 'Date');
             assert.equal(Number(err.expiredAt), 1437018642000);
             assert.isUndefined(result);
             done();
           }

         });

      it('should not error for claims issued before a certain timespan but still inside clockTolerance timespan',
         function(done) {
           var clockTimestamp = 1437018592;  // iat + 10s
           var options = {
             algorithms: ['HS256'],
             clockTimestamp: clockTimestamp,
             maxAge: '3s',
             clockTolerance: 10
           };

           var key = 'secret';
           var basicIdToken =
               new BasicIdToken('issuer', 'subject', clockTimestamp, 'jti');
           basicIdToken.addOptionalClaims(
               {'foo': 'bar', 'aud': 'audience', 'exp': clockTimestamp + 10});
           basicIdToken.setNoneAlgorithm(true);
           var token = basicIdToken.toJWT(key);

           try {
             var result = basicIdToken.fromJWT(
                 token, key, {
                   'iss': 'issuer',
                   'sub': 'subject',
                   'aud': 'audience',
                   'maxAge': '3s',
                   'clockTolerance': 10,
                   'jti': 'jti'
                 },
                 options);
           } catch (err) {
             assert.isNull(err);
             assert.equal(result.foo, 'bar');
           }
           done();

         });

      it('should not error if within maxAge timespan', function(done) {
        var clockTimestamp = 1437018587;  // iat + 5s
        var options = {
          algorithms: ['HS256'],
          clockTimestamp: clockTimestamp,
          maxAge: '6s'
        };

        try {
          var result = basicIdToken.fromJWT(
              token, key, {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '6s',
                'clockTolerance': 10,
                'jti': 'jti'
              },
              options);
        } catch (err) {
          assert.isNull(err);
          assert.equal(result.foo, 'bar');
        }
        done();

      });

      it('can be more restrictive than expiration', function(done) {
        var clockTimestamp = 1437018588;  // iat + 6s
        var options = {
          algorithms: ['HS256'],
          clockTimestamp: clockTimestamp,
          maxAge: '5s'
        };

        var key = 'secret';
        var basicIdToken =
            new BasicIdToken('issuer', 'subject', clockTimestamp - 6, 'jti');
        basicIdToken.addOptionalClaims({'foo': 'bar', 'aud': 'audience'});
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT(key);

        try {
          var result = basicIdToken.fromJWT(
              token, key, {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '5s',
                'jti': 'jti'
              },
              options);
        } catch (err) {
          assert.equal(err.name, 'TokenExpiredError');
          assert.equal(err.message, 'maxAge exceeded');
          assert.equal(err.expiredAt.constructor.name, 'Date');
          assert.equal(Number(err.expiredAt), 1437018587000);
          assert.isUndefined(result);
          done();
        }
      });

      it('cannot be more permissive than expiration', function(done) {
        var clockTimestamp = 1437018900;  // iat + 318s (exp: iat + 218s)
        var options = {
          algorithms: ['HS256'],
          clockTimestamp: clockTimestamp,
          maxAge: '1000y'
        };

        try {
          var result = basicIdToken.fromJWT(
              token, key, {
                'iss': 'issuer',
                'sub': 'subject',
                'aud': 'audience',
                'maxAge': '1000y',
                'clockTolerance': 10,
                'jti': 'jti'
              },
              options);

        } catch (err) {
          // maxAge not exceded, but still expired
          assert.equal(err.name, 'TokenExpiredError');
          assert.equal(err.message, 'jwt expired');
          assert.equal(err.expiredAt.constructor.name, 'Date');
          assert.equal(Number(err.expiredAt), 1437018800000);
          assert.isUndefined(result);
          done();
        }

        /*
        jwt.verify(token, key, options, function (err, p) {
          // maxAge not exceded, but still expired
          assert.equal(err.name, 'TokenExpiredError');
          assert.equal(err.message, 'jwt expired');
          assert.equal(err.expiredAt.constructor.name, 'Date');
          assert.equal(Number(err.expiredAt), 1437018800000);
          assert.isUndefined(p);
          done();
        });*/
      });

      it('should error if maxAge is specified but there is no iat claim',
         function(done) {
           var clockTimestamp = 1437018582;
           // var token =
           // 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.0MBPd4Bru9-fK_HY3xmuDAc6N_embknmNuhdb9bKL_U';
           var options = {algorithms: ['HS256'], maxAge: '1s'};

           /*jwt.verify(token, key, options, function (err, p) {
             assert.equal(err.name, 'JsonWebTokenError');
             assert.equal(err.message, 'iat required when maxAge is specified');
             assert.isUndefined(p);
             done();
           });*/

           var clockTimestamp = 1437018582;
           // var token =
           // 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmb28iOiJiYXIifQ.0MBPd4Bru9-fK_HY3xmuDAc6N_embknmNuhdb9bKL_U';
           var options = {
             algorithms: ['HS256'],
             clockTimestamp: clockTimestamp,
             maxAge: '1s'
           };
           var key = 'secret';
           var refreshToken = new RefreshToken('refreshToken', 'accessToken');
           var token = refreshToken.toJWT(key, {noTimestamp: true});
           try {
             var result = refreshToken.fromJWT(
                 token, key, {
                   'refreshToken': 'refreshToken',
                   'accessToken': 'accessToken',
                   'maxAge': '1s'
                 },
                 options);
           } catch (err) {
             assert.equal(err.name, 'JsonWebTokenError');
             assert.equal(err.message, 'iat required when maxAge is specified');
             assert.isUndefined(result);
             done();
           }
         });
    });
  });
});