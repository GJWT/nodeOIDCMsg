var jwt = require('../index');
var expect = require('chai').expect;
var jws = require('../node_modules/src/controllers/messageTypes/jwt/lib/jws');
var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');

describe('signing a token asynchronously', function() {
    var clockTimestamp = 1000000000;  
    
  describe('when signing a token', function() {
    var secret = 'shhhhhh';

    it('should return the same result as singing synchronously', function(done) {
        var secret = "shhhh";
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({ "foo": "bar", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : 1});
        basicIdToken.setNoneAlgorithm(true);
        basicIdToken.toJWT(secret, { algorithm: 'HS256'}, function (err, asyncToken) {
     // jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' }, function (err, asyncToken) {
        if (err) return done(err);

        var secret = "shhhh";
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({ "foo": "bar", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : 1});
        basicIdToken.setNoneAlgorithm(true);
        var syncToken = basicIdToken.toJWT(secret, { algorithm: 'HS256'});

        //var syncToken = jwt.sign({ foo: 'bar' }, secret, { algorithm: 'HS256' });
        expect(asyncToken).to.be.a('string');
        expect(asyncToken.split('.')).to.have.length(3);
        expect(asyncToken).to.equal(syncToken);
        done();
      });
    });

    it('should work with empty options', function (done) {
        try{
            var secret = "secret";
            var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
            basicIdToken.addNonStandardClaims({ "abc": 1, "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : 1});
            basicIdToken.setNoneAlgorithm(true);
            var syncToken = basicIdToken.toJWT(secret, {});
        }catch(err){
            expect(err).to.be.null();
        }
        done();
        
        /*
      jwt.sign({abc: 1}, "secret", {}, function (err, res) {
        expect(err).to.be.null();
        done();
      });*/
    });

    it('should work without options object at all', function (done) {

        try{
            var secret = "secret";
            var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
            basicIdToken.addNonStandardClaims({ "abc": 1, "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : 1});
            basicIdToken.setNoneAlgorithm(true);
            var syncToken = basicIdToken.toJWT(secret);
        }catch(err){
            expect(err).to.be.null();
        }
        done();
        

      /*jwt.sign({abc: 1}, "secret", function (err, res) {
        expect(err).to.be.null();
        done();
      });*/
    });

    it('should work with none algorithm where secret is set', function(done) {

        try{
            var secret = "secret";
            var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
            basicIdToken.addNonStandardClaims({  foo: 'bar' , "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : 1});
            basicIdToken.setNoneAlgorithm(true);
            var token = basicIdToken.toJWT(secret, { algorithm: 'none' });
            expect(token).to.be.a('string');
            expect(token.split('.')).to.have.length(3);
        }catch(err){
            expect(err).to.be.null();
        }
        done();
        
        /*
      jwt.sign({ foo: 'bar' }, 'secret', { algorithm: 'none' }, function(err, token) {
        expect(token).to.be.a('string');
        expect(token.split('.')).to.have.length(3);
        done();
      });*/
    });

    //Known bug: https://github.com/brianloveswords/node-jws/issues/62
    //If you need this use case, you need to go for the non-callback-ish code style.
    it.skip('should work with none algorithm where secret is falsy', function(done) {
        try{
            var secret = "secret";
            var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
            basicIdToken.addNonStandardClaims({  foo: 'bar' , "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : 1});
            basicIdToken.setNoneAlgorithm(true);
            var token = basicIdToken.toJWT(undefined, { algorithm: 'none' });
            expect(token).to.be.a('string');
            expect(token.split('.')).to.have.length(3);
        }catch(err){
            expect(err).to.be.null();
        }
        done();
        
    /*
      jwt.sign({ foo: 'bar' }, undefined, { algorithm: 'none' }, function(err, token) {
        expect(token).to.be.a('string');
        expect(token.split('.')).to.have.length(3);
        done();
      });*/
    });

    it('should return error when secret is not a cert for RS256', function(done) {
      //this throw an error because the secret is not a cert and RS256 requires a cert.
      try{
        var secret = "secret";
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({  foo: 'bar' , "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : 1});
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT(secret, { algorithm: 'RS256'});
        expect(token).to.be.a('string');
        expect(token.split('.')).to.have.length(3);
      }catch(err){
        expect(err).to.be.ok();
      }
      done();
    
    /*
      jwt.sign({ foo: 'bar' }, secret, { algorithm: 'RS256' }, function (err) {
        expect(err).to.be.ok();
        done();
      });*/
    });

    it('should return error on wrong arguments', function(done) {
      //this throw an error because the secret is not a cert and RS256 requires a cert.
      //this throw an error because the secret is not a cert and RS256 requires a cert.
      try{
        var secret = "secret";
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({  'foo': 'bar' , "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : 1});
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT(secret, {notBefore: {}});
      }catch(err){
        expect(err).to.be.ok();
      }
    done();
    
      /*
      jwt.sign({ foo: 'bar' }, secret, { notBefore: {} }, function (err) {
        expect(err).to.be.ok();
        done();
      });*/
    });

    it('should return error on wrong arguments (2)', function(done) {
        try{
            var secret = "secret";
            var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
            basicIdToken.addNonStandardClaims({  foo: 'bar' , "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : 1});
            basicIdToken.setNoneAlgorithm(true);
            var token = basicIdToken.toJWT(secret, {noTimestamp: true});
          }catch(err){
            expect(err).to.be.ok();
            expect(err).to.be.instanceof(Error);
          }
        done();
        
        /*
      jwt.sign('string', 'secret', {noTimestamp: true}, function (err) {
        expect(err).to.be.ok();
        expect(err).to.be.instanceof(Error);
        done();
      });*/
    });

    it('should not stringify the payload', function (done) {
      /*jwt.sign('string', 'secret', {}, function (err, token) {
        if (err) { return done(err); }
        expect(jws.decode(token).payload).to.equal('string');
        done();
      });*/

      try{
        var secret = "secret";
        var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
        basicIdToken.addNonStandardClaims({  'payload': 'string' , "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
        basicIdToken.setNoneAlgorithm(true);
        var token = basicIdToken.toJWT(secret, {});
       var result = basicIdToken.fromJWT(token, secret, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"}, {'clockTimestamp' : clockTimestamp});        
        
        expect(result.payload).to.equal('string');
      }catch(err){
        expect(err).to.be.null();
      }
      done();
    
    });

    describe('secret must have a value', function(){
      [undefined, '', 0].forEach(function(secret){
        it('should return an error if the secret is falsy and algorithm is not set to none: ' + (typeof secret === 'string' ? '(empty string)' : secret), function(done) {
        // This is needed since jws will not answer for falsy secrets
          try{
            var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
            basicIdToken.addNonStandardClaims({   "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
            basicIdToken.setNoneAlgorithm(true);
            var token = basicIdToken.toJWT(secret, {});
          }catch(err){
            expect(err).to.be.exist();
            expect(err.message).to.equal('secretOrPrivateKey must have a value');
            expect(token).to.not.exist;     
            done();
            
          }
        
          /*jwt.sign('string', secret, {}, function(err, token) {
            expect(err).to.be.exist();
            expect(err.message).to.equal('secretOrPrivateKey must have a value');
            expect(token).to.not.exist;
            done();
          });*/
        });
      });
    });
  });
});
