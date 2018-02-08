var jwt = require('../index');
var fs = require('fs');
var path = require('path');
var expect = require('chai').expect;
var assert = require('chai').assert;
var ms = require('ms');
var ImplicitAccessToken = require('../src/models/tokenProfiles/implicitAccessToken');

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
    // openssl ecparam -name secp256r1 -genkey -param_enc explicit -out ecdsa-private.pem
    priv_key: loadKey('ecdsa-private.pem'),
    // openssl ec -in ecdsa-private.pem -pubout -out ecdsa-public.pem
    pub_key: loadKey('ecdsa-public.pem'),
    invalid_pub_key: loadKey('ecdsa-public-invalid.pem')
  }
};


describe('Asymmetric Algorithms', function(){

  Object.keys(algorithms).forEach(function (algorithm) {
    describe(algorithm, function () {
      var clockTimestamp = 1000000000;
      
      var pub = algorithms[algorithm].pub_key;
      var priv = algorithms[algorithm].priv_key;

      describe('when signing a token with a known non standard claim', function () {
        var implicitAccessToken = new ImplicitAccessToken('issuer','subject', clockTimestamp);
        implicitAccessToken.addOptionalClaims({"aud" : "audience"});
        implicitAccessToken.setNoneAlgorithm(true);
        var signedJWT = implicitAccessToken.toJWT('shhhh');

        it('should check known non standard claim', function (done) {
          try{
            var decodedPayload = implicitAccessToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d'},{'clockTimestamp' : clockTimestamp});
            assert.isNotNull(decodedPayload);
            done();            
          }catch(err){
            assert.isNull(err);
            done();
          }

        it('should throw when invalid known non standard claim', function (done) {
         
          try{
            var decodedPayload = implicitAccessToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "wrong-audience", 'maxAge': '1d'}, {'clockTimestamp' : clockTimestamp});
          }catch(err){
            assert.isNotNull(err);
            done();
          }
        });
      });
    });
       
  
      describe('when signing a token without standard claim', function () {
        it('should throw error and require standard claim', function (done) {
          try{
            var implicitAccessToken = new ImplicitAccessToken('issuer','subject');
            implicitAccessToken.addOptionalClaims({"jti" : "test"});
            implicitAccessToken.setNoneAlgorithm(true);
            var signedJWT = implicitAccessToken.toJWT('shhhh');
          }catch(err){
            assert.isNotNull(err);
            assert.instanceOf(err, Error);
            done();
          }
        });
      });

    describe('when adding claims to token profile', function () {
      var dateNow = Math.floor(Date.now() / 1000);
      var iat = dateNow - 30;
      var expiresIn = 50;
      var clockTimestamp = 1000000000;

      var implicitAccessToken = new ImplicitAccessToken('issuer','subject', clockTimestamp);
      implicitAccessToken.addOptionalClaims({"aud" : "audience"});
      implicitAccessToken.setNoneAlgorithm(true);        

      it('should be able to access all standard claims', function (done) {
        try{
         var standardClaims = implicitAccessToken.getRequiredClaims();  
         assert.deepEqual(standardClaims, { "iss" : "issuer", "sub" : 'subject',  "iat" : clockTimestamp})          
        }catch(err){
          assert.isNull(err);
        }
        done();
      });

      it('should be able to access non standard claims separately', function (done) {
          try{
           var nonStandardClaims = implicitAccessToken.getOptionalClaims();  
           assert.deepEqual(nonStandardClaims, {"aud" : "audience"})          
          }catch(err){
            assert.isNull(err);
          }
          done();
        });
    });      

    describe('when signing a token with standard claim', function () {
      var implicitAccessToken = new ImplicitAccessToken('issuer','subject', clockTimestamp);
      implicitAccessToken.setNoneAlgorithm(true);
      var signedJWT = implicitAccessToken.toJWT('shhhh');

      it('should check standard claim', function (done) {
      
        try{
          var decodedPayload = implicitAccessToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d'}, {'clockTimestamp' : clockTimestamp});
        }catch(err){
          assert.isNotNull(decodedPayload);
          assert.isNull(err);
        }
        done();
      });

      
      it('should throw when invalid standard claim', function (done) {
        try{
          var decodedPayload = implicitAccessToken.fromJWT(signedJWT, 'shhhh', {"iss" : "wrong-issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d'}, {'clockTimestamp' : clockTimestamp});
        }catch(err){

          assert.isNotNull(err);
          assert.equal(err.name, 'JsonWebTokenError');
          done();
        }
      });
    }); 
  });
});
}); 

