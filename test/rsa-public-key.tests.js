var jwt = require('../');
var fs = require('fs');
var path = require('path');
var pub = fs.readFileSync(path.join(__dirname, 'pub.pem'), 'utf8');
var clockTimestamp = 1000000000;
var BasicIdToken = require('../node_modules/src/models/tokenProfiles/basicIdToken');

describe('public key start with BEGIN RSA PUBLIC KEY', function () {

  it('should work', function (done) {
    var fs = require('fs');
    var cert_pub = fs.readFileSync(__dirname + '/rsa-public-key.pem');
    var cert_priv = fs.readFileSync(__dirname + '/rsa-private.pem');

    var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
    basicIdToken.addNonStandardClaims({"foo":"bar", "aud" : "audience", "nbf" : clockTimestamp + 2, "exp" : clockTimestamp + 3});
    basicIdToken.setNoneAlgorithm(true);
    var signedJWT = basicIdToken.toJWT(cert_priv, {algorithm : 'RS256'});

    var decodedPayload = basicIdToken.fromJWT(signedJWT, cert_pub, {"iss" : "issuer", "sub": "subject", "aud" : "audience", 'maxAge': '1d', 'clockTolerance' : 10, "jti": "jti"},{'clockTimestamp' : clockTimestamp}, done);        

  });

});