var jwt = require('../index');
var expect = require('chai').expect;
var JsonWebTokenError = require('../src/controllers/messageTypes/jwt/jsonwebtoken/lib/JsonWebTokenError');
var BasicIdToken = require('../src/models/tokenProfiles/basicIdToken');

describe('non_object_values values', function() {

  it('should work with string', function () {
    /*var token = jwt.sign('hello', '123');
    var result = jwt.verify(token, '123');
    expect(result).to.equal('hello');*/
    var clockTimestamp = 1000000000;
    
    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addOptionalClaims({"hello": "hello", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('123', {algorithm : 'HS256'});

    var result = basicIdToken.fromJWT(signedJWT, '123', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});        
    expect(result.hello).to.equal('hello');
    
  });

  //v6 version will throw in this case:
  /*
  it('should throw with expiresIn', function () {
    expect(function () {
      //jwt.sign('hello', '123', { expiresIn: '12h' });

      var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
      basicIdToken.addOptionalClaims({"hello": "hello", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
      basicIdToken.setNoneAlgorithm(true);
      var signedJWT = basicIdToken.toJWT('123', {algorithm : 'HS256', expiresIn: '12h'});
    }).to.throw(/invalid expiresIn option for string payload/);
  });
  */

  /*
  it('should fail to validate audience when the payload is string', function () {
    var token = jwt.sign('hello', '123');
    expect(function () {
      jwt.verify(token, '123', { audience: 'foo' });
    }).to.throw(JsonWebTokenError);
  });*/

  it('should work with number', function () {
    var clockTimestamp = 1000000000;
    
    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addOptionalClaims({"data": 123, "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('123', {algorithm : 'HS256'});
  
    var result = basicIdToken.fromJWT(signedJWT, '123', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});        
    expect(result.data).to.equal(123);
  });

});