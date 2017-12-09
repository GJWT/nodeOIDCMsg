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

var expect = require('chai').expect;
var jwt = require('./..');
var atob = require('atob');
var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');
var clockTimestamp = 1000000000;

describe('issue 196', function () {
  function b64_to_utf8 (str) {
    return decodeURIComponent(escape(atob( str )));
  }

  it('should use issuer provided in payload.iss', function () {

    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"hello": "hello", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var token = basicIdToken.toJWT('123', {algorithm : 'HS256', "keyid": "1234"});
    var decoded_issuer = JSON.parse(b64_to_utf8(token.split('.')[1])).iss;
    expect(decoded_issuer).to.equal('issuer');
  });
});