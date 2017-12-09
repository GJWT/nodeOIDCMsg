// Copyright (c) 2017 The Authors of 'JWTS for NODE'
//
// Permission is hereby granted, free of charge, to any person obtaining a copy of
// this software and associated documentation files (the "Software"), to deal in
// the Software without restriction, including without limitation the rights to
// use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
// the Software, and to permit persons to whom the Software is furnished to do so,
// subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
// FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
// COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
// IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

var jwt = require('../index');
var expect = require('chai').expect;
var JsonWebTokenError = require('../node_modules/src/controllers/messageTypes/jwt/jsonwebtoken/lib/JsonWebTokenError');
var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');

describe('non_object_values values', function() {

  it('should work with string', function () {
    /*var token = jwt.sign('hello', '123');
    var result = jwt.verify(token, '123');
    expect(result).to.equal('hello');*/
    var clockTimestamp = 1000000000;
    
    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"hello": "hello", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
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
      basicIdToken.addNonStandardClaims({"hello": "hello", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
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
    basicIdToken.addNonStandardClaims({"data": 123, "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('123', {algorithm : 'HS256'});
  
    var result = basicIdToken.fromJWT(signedJWT, '123', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp});        
    expect(result.data).to.equal(123);
  });

});