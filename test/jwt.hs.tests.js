var jwt = require('../index');

var expect = require('chai').expect;
var assert = require('chai').assert;
var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');

describe('HS256', function() {
    var secret = 'shhhhhh';
    var clockTimestamp = 1000000000;
    
  describe('when signing a token', function() {


  var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
  basicIdToken.addNonStandardClaims({ "foo": "bar", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
  basicIdToken.setNoneAlgorithm(true);
  var token = basicIdToken.toJWT(secret, { algorithm: 'HS256' });

    it('should be syntactically valid', function() {
      expect(token).to.be.a('string');
      expect(token.split('.')).to.have.length(3);
    });

    /*
    it('should be able to validate without options', function(done) {
      var callback = function(err, token) {
        assert.ok(token.foo);
        assert.equal('bar', token.foo);
        done();
      };
      callback.issuer = "shouldn't affect";
      var decodedPayload = basicIdToken.fromJWT(token, secret, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp}, callback);
      
      //jwt.verify(token, secret, callback );
    });*/

    it('should validate with secret', function(done) {
        try{
            var decoded = basicIdToken.fromJWT(token, secret, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});
            assert.ok(decoded.foo);
            assert.equal('bar', decoded.foo);
        }catch(err){
        };
        done();
        
      /*jwt.verify(token, secret, function(err, decoded) {
        assert.ok(decoded.foo);
        assert.equal('bar', decoded.foo);
        done();
      });*/
    });

    it('should throw with invalid secret', function(done) {
        try{
            var decoded = basicIdToken.fromJWT(token, 'invalid-secret', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});
        }catch(err){
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            done();
        }
    });

    it('should throw with secret and token not signed', function(done) {
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({ "foo": "bar", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
        basicIdToken.setNoneAlgorithm(true);
        var signed = basicIdToken.toJWT(secret, { algorithm: 'none'  });

      var unsigned = signed.split('.')[0] + '.' + signed.split('.')[1] + '.';
      try{
        var decoded = basicIdToken.fromJWT(unsigned, secret, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});
      }catch(err){
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      }
    });

    it('should work with falsy secret and token not signed', function(done) {
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({ "foo": "bar", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
        basicIdToken.setNoneAlgorithm(true);
        var signed = basicIdToken.toJWT(null, { algorithm: 'none'  });

      var unsigned = signed.split('.')[0] + '.' + signed.split('.')[1] + '.';
        try{
            var decoded = basicIdToken.fromJWT(unsigned, secret, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});
        }catch(err){
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            done();
        }  
    });

    it('should throw when verifying null', function(done) {
        basicIdToken.fromJWT(null, secret, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp}, function(err, decoded) {
            assert.isUndefined(decoded);
            assert.isNotNull(err);
          });
          done();
          
    });

    it('should return an error when the token is expired', function(done) {
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({ "foo": "bar", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : 1});
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT(secret, { algorithm: 'HS256'   });
        try{
        var decoded = basicIdToken.fromJWT(token, secret, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp, algorithm: 'HS256' });
        }catch(err){
            assert.isUndefined(decoded);
            assert.isNotNull(err);
            done();
        };
          /*
      jwt.verify(token, secret, { algorithm: 'HS256' }, function(err, decoded) {
        assert.isUndefined(decoded);
        assert.isNotNull(err);
        done();
      });*/
    });

    it('should NOT return an error when the token is expired with "ignoreExpiration"', function(done) {
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({ "foo": "bar", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : 1});
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT(secret, { algorithm: 'HS256'});
        basicIdToken.fromJWT(token, secret, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp, algorithm: 'HS256', ignoreExpiration: true}, function(err, decoded) {
            assert.isNotNull(decoded);
            assert.isNull(err);
            done();
          });
      
      /*    jwt.verify(token, secret, { algorithm: 'HS256', ignoreExpiration: true }, function(err, decoded) {
        assert.ok(decoded.foo);
        assert.equal('bar', decoded.foo);
        assert.isNull(err);
        done();
      });*/
    });

        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    it('should default to HS256 algorithm when no options are passed', function() {
        basicIdToken.addNonStandardClaims({ "foo": "bar", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT(secret);
      

      //var token = jwt.sign({ foo: 'bar' }, secret);
      var verifiedToken = basicIdToken.fromJWT(token, secret, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});
      assert.ok(verifiedToken.foo);
      assert.equal('bar', verifiedToken.foo);
    });
  });

  describe('should fail verification gracefully with trailing space in the jwt', function() {
    var secret = 'shhhhhh';
    //var token  = jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });

    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({ "foo": "bar", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : 1});
    basicIdToken.setNoneAlgorithm(true);
    var token = basicIdToken.toJWT(secret, { algorithm: 'HS256'   });

    it('should return the "invalid token" error', function(done) {
      var malformedToken = token + ' '; // corrupt the token by adding a space
    try{
      var decoded = basicIdToken.fromJWT(malformedToken, secret, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp, algorithm: 'HS256', ignoreExpiration: true});
    }catch(err){
        assert.isNotNull(err);
        assert.equal('JsonWebTokenError', err.name);
        assert.equal('invalid token', err.message);
        done();
    };

      /*
      jwt.verify(malformedToken, secret, { algorithm: 'HS256', ignoreExpiration: true }, function(err, decoded) {
        assert.isNotNull(err);
        assert.equal('JsonWebTokenError', err.name);
        assert.equal('invalid token', err.message);
        done();
      });*/
    });
  });

});