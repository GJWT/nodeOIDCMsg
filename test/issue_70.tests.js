var jwt = require('../');
var clockTimestamp = 1000000000;
var BasicIdToken = require('../src/models/tokenProfiles/basicIdToken');

describe('issue 70 - public key start with BEING PUBLIC KEY', function () {

  it('should work', function (done) {
    var fs = require('fs');
    var cert_pub = fs.readFileSync(__dirname + '/rsa-public.pem');
    var cert_priv = fs.readFileSync(__dirname + '/rsa-private.pem');

    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addOptionalClaims({"foo":"bar", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT(cert_priv, {algorithm : 'RS256'});

    var decodedPayload = basicIdToken.fromJWT(signedJWT, cert_pub, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp}, done);        
  });
});
