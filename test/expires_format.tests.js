var expect = require('chai').expect;
var BasicIdToken = require('../src/oicMsg/tokenProfiles/basicIdToken');
var assert = require('chai').assert;

describe('expires option', function() {
  it('should work with a number of seconds', function(done) {
    var dateNow = Math.floor(Date.now() / 1000);
    var iat = dateNow;
    var basicIdToken =
        new BasicIdToken({iss: 'issuer', sub: 'subject', iat: iat, jti: 'jti'});
    basicIdToken.addOptionalClaims({'aud': 'audience'});
    basicIdToken.toJWT('shhhh', {expiresIn: 10})
        .then(function(signedJWT) {
          var verificationClaims = {
            'iss': 'issuer',
            'sub': 'subject',
            'aud': 'audience',
            'maxAge': '1d',
            'jti': 'jti',
            'clockTolerance': 10
          };
          basicIdToken
              .fromJWT(
                  signedJWT, 'shhhh', verificationClaims,
                  {algorithms: ['HS256'], clockTimestamp: dateNow})
              .then(function(decodedPayload) {
                expect(decodedPayload.exp).to.be.closeTo(iat + 10, 0.2);
                assert.isNotNull(decodedPayload);
              })
              .catch(function(err) {
                assert.isNull(err);
              });
        })
        .catch(function(err) {
          assert.isNull(err);
        });
    done();
  });

  it('should work with a string', function(done) {
    var two_days_in_secs = 2 * 24 * 60 * 60;

    var dateNow = Math.floor(Date.now() / 1000);
    var iat = dateNow - 30;
    var basicIdToken =
        new BasicIdToken({iss: 'issuer', sub: 'subject', iat: iat, jti: 'jti'});
    basicIdToken.addOptionalClaims({'aud': 'audience'});
    basicIdToken.toJWT('shhhh', {expiresIn: '2d'})
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
                    .to.be.closeTo(iat + two_days_in_secs, 0.2);
                assert.isNotNull(decodedPayload);
              })
              .catch(function(err) {
                assert.isNull(err);
              });
        });
    done();
  });

  it('should work with a string second example', function(done) {
    var day_and_a_half_in_secs = 1.5 * 24 * 60 * 60;

    var dateNow = Math.floor(Date.now() / 1000);
    var iat = dateNow - 30;
    var basicIdToken =
        new BasicIdToken({iss: 'issuer', sub: 'subject', iat: iat, jti: 'jti'});
    basicIdToken.addOptionalClaims({'aud': 'audience'});
    basicIdToken.toJWT('shhhh', {expiresIn: '36h'})
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
                    .to.be.closeTo(iat + day_and_a_half_in_secs, 0.2);
                assert.isNotNull(decodedPayload);
              })
              .catch(function(err) {
                assert.isNull(err);
              });
        })
        .catch(function(err) {
          assert.isNull(err);
        });
    done();
  });

  it('should throw if expires has a bad string format', function(done) {


    expect(function() {

      var dateNow = Math.floor(Date.now() / 1000);
      var iat = dateNow - 30;
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: iat, jti: 'jti'});
      basicIdToken.addOptionalClaims({'aud': 'audience'});
      basicIdToken.toJWT('shhhh', {expiresIn: '1 monkey'});
      done();
    })
        .to.throw(
            /"expiresIn" should be a number of seconds or string representing a timespan/);
    done();


  });

  it('should throw if expires is not an string or number', function(done) {
    expect(function() {
      var dateNow = Math.floor(Date.now() / 1000);
      var iat = dateNow - 30;
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: iat, jti: 'jti'});
      basicIdToken.addOptionalClaims({'aud': 'audience'});
      basicIdToken.toJWT('shhhh', {expiresIn: {crazy: 213}});
      done();
    })
        .to.throw(
            /"expiresIn" should be a number of seconds or string representing a timespan/);
    done();

  });

  it('should throw an error if expiresIn and exp are provided', function(done) {
    expect(function() {

      var dateNow = Math.floor(Date.now() / 1000);
      var iat = dateNow - 30;
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: iat, jti: 'jti'});
      basicIdToken.addOptionalClaims({'aud': 'audience', exp: 839218392183});
      basicIdToken.toJWT('shhhh', {expiresIn: '5h'});
      done();
    })
        .to.throw(
            /Bad "options.expiresIn" option the payload already has an "exp" property./);
    done();
  });


  it('should throw on deprecated expiresInSeconds option', function(done) {
    expect(function() {
      var dateNow = Math.floor(Date.now() / 1000);
      var iat = dateNow - 30;
      var basicIdToken = new BasicIdToken(
          {iss: 'issuer', sub: 'subject', iat: iat, jti: 'jti'});
      basicIdToken.addOptionalClaims({'aud': 'audience', exp: 839218392183});
      basicIdToken.toJWT('shhhh', {expiresInSeconds: 5});
      done();
    }).to.throw('"expiresInSeconds" is not allowed');
    done();

  });


});
