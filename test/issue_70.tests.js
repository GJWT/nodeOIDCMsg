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

var jwt = require('../');
var clockTimestamp = 1000000000;
var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');

describe('issue 70 - public key start with BEING PUBLIC KEY', function () {

  it('should work', function (done) {
    var fs = require('fs');
    var cert_pub = fs.readFileSync(__dirname + '/rsa-public.pem');
    var cert_priv = fs.readFileSync(__dirname + '/rsa-private.pem');

    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"foo":"bar", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT(cert_priv, {algorithm : 'RS256'});

    var decodedPayload = basicIdToken.fromJWT(signedJWT, cert_pub, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp}, done);        
  });
});
