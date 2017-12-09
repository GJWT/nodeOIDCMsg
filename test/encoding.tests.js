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
var atob = require('atob');

var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');

describe('encoding', function() {
    var clockTimestamp = 1000000000;
    
  function b64_to_utf8 (str) {
    return decodeURIComponent(escape(atob( str )));
  }

  it('should properly encode the token (utf8)', function () {
    var expected = 'José';

    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"name" : expected, "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('shhhh');

    var decoded_name = JSON.parse(b64_to_utf8(signedJWT.split('.')[1])).name;
    expect(decoded_name).to.equal(expected);
  });

  
  it('should properly encode the token (binary)', function () {
    var expected = 'José';

    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"name" : expected, "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3}, { encoding: 'binary' });
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('shhhh', {encoding: 'binary' });

    var decoded_name = JSON.parse(atob(signedJWT.split('.')[1])).name;
    expect(decoded_name).to.equal(expected);
  });

  it('should return the same result when decoding', function () {
    var username = '測試';

    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"username" : username, "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT('shhhh');

    var payload = basicIdToken.fromJWT(signedJWT, 'shhhh', {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"}, {'clockTimestamp' : clockTimestamp});
    expect(payload.username).to.equal(username);
    
  });

});