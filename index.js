  /* Main */

  var clockTimestamp = 1000000000; 
  var BasicIdToken = require('./node_modules/src/models/tokenProfiles/basicIdToken');  
  //var GoogleIdToken = require('./node_modules/src/models/tokenProfiles/googleIdToken');
  //var RefreshToken = require('./node_modules/src/models/tokenProfiles/refreshToken');
  var clockTimestamp = 1000000000; 
  var expect = require('chai').expect;
  var atob = require('atob');
  var assert = require('chai').assert;  
  var XMLHttpRequest = require("xmlhttprequest").XMLHttpRequest;
  var jwtDecoder = require('./node_modules/src/controllers/messageTypes/jwt/jsonwebtoken/decode');  
  var conv = require('binstring');
  var KeyBundle = require('./node_modules/src/models/keystore-dependency/keyBundle');  
  
  var clockTimestamp = 1511783267;

  /*
  var kb = new KeyBundle(null, "/Users/anjuthomas/Documents/jwks2.json", 'jwks');
  setTimeout(function () {
   /* var k = kb.getKeyWithKid('rsa1');
    console.log(k.kid)
    console.log(k.kty)
    console.log(kb.getKty('OCT'));
    console.log(kb.getKty('RSA'));
    console.log(kb.getKty('EC'));
    //console.log(k.kid)
    //console.log(k.kty)
  }, 5000);*/

  /*
  var kb = KeyBundle(null, "/Users/anjuthomas/Documents/id_rsa.pub", "der", ['sig'])
  setTimeout(function () {
    console.log(kb.getJwks());
  }, 5000);*/

  /*

  var desc = {
    "kty": "RSA",
    "e": "AQAB",
    "use": "enc",
    "kid": "Jb8ZVEFoN1OZjdMoO6H7csDR8UPRtwgmXV6i2uzbGkY",    
    "n": "inLw-BGYXhic6qS__NBRDfCqFF07lyyBO_tyoBk_EqVoyog03NzcBsKbOHFS3mtu81uBzyDA_lzVZGOacovYo3zteo2o1JrJ97LpgOa1CDgxR8KpzDXiWRRbkkIG7JvO_h9ghCfZghot-kn5JLgCRAbuMhiRT2ojdhU_nhjywI0"
  };
  var kb = new KeyBundle([desc]);
  console.log(kb.getKeys())

  /*for (var k in kb.getKeys()){
    var keys = kb.getKeys();
    kb.remove(keys[k]);
  }*/
/*
  for (var k in kb.getKeys()){
    var keys = kb.getKeys();
    //kb.remove(keys[k]);
    kb.markAsInactive(keys[k].kid)
  }
  console.log("After inactive key added")
  console.log(kb.getKeys());


  var desc = {
    "kty": "RSA",
    "e": "AQAB",
    "use": "enc",
    "kid": "Jb8ZVEFoN1OZjdMoO6H7csDR8UPRtwgmXV6i2uzbGkY",    
    "n": "inLw-BGYXhic6qS__NBRDfCqFF07lyyBO_tyoBk_EqVoyog03NzcBsKbOHFS3mtu81uBzyDA_lzVZGOacovYo3zteo2o1JrJ97LpgOa1CDgxR8KpzDXiWRRbkkIG7JvO_h9ghCfZghot-kn5JLgCRAbuMhiRT2ojdhU_nhjywI0"
  };
  kb.doKeys([desc]);
  console.log("After doKeys on desc")  
  console.log(kb.getKeys())

  console.log(kb.activeKeys());


  /*var kb = new KeyBundle(null, "/Users/anjuthomas/Documents/jwk.json", 'jwks');
  console.log("_________________________________")

  setTimeout(function () {
    console.log(kb.getKeys());    
}, 5000);*/

/*
var kb = new KeyBundle(null, source='/Users/anjuthomas/Documents/rsa_enc.pub', fileformat='der', keyusage=['sig'])
setTimeout(function () {
  console.log(kb.getKeys());    
}, 5000);

/*

  var desc = {
    "kty": "RSA",
    "e": "AQAB",
    "use": "enc",
    "n": "inLw-BGYXhic6qS__NBRDfCqFF07lyyBO_tyoBk_EqVoyog03NzcBsKbOHFS3mtu81uBzyDA_lzVZGOacovYo3zteo2o1JrJ97LpgOa1CDgxR8KpzDXiWRRbkkIG7JvO_h9ghCfZghot-kn5JLgCRAbuMhiRT2ojdhU_nhjywI0"
  };
  var kb = new KeyBundle([desc]);
  //console.log(kb.getKeys());

  var keyList = [
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "enc",
      "n": "inLw-BGYXhic6qS__NBRDfCqFF07lyyBO_tyoBk_EqVoyog03NzcBsKbOHFS3mtu81uBzyDA_lzVZGOacovYo3zteo2o1JrJ97LpgOa1CDgxR8KpzDXiWRRbkkIG7JvO_h9ghCfZghot-kn5JLgCRAbuMhiRT2ojdhU_nhjywI0"
    },
    {
      "kty": "RSA",
      "e": "AQAB",
      "use": "sig",
      "n": "0eAoiw_xP35yXeJJSNrjhplu32XhEaRpYIshCP-8FvktNnbULFKF_2hHQ7c7iPpmZS7-U8zEQn3O-ZrVDw9u4Ito0FvQ2fw7eZNNxsb8WlZHW07e_y2xByYfwfQhk3Nn9yqb5xSfdaVAUaRFPFSxE_gOu6iaWGp8lz-fyznxaDk"
    }
  ];
  var kb = new KeyBundle(keyList);
  //console.log(kb.getKeys());

  var kb = new KeyBundle([], 'https://sandrino.auth0.com/.well-known/jwks.json', 'jwks');
  console.log(kb.getKeys());
  */
  /*
  var jwk = {
    "keys": [
      {
        "use": "enc",
        "n": "z7TYSonR4KTijDVTJJHBRs_7MUtvy2_aIPOKpkbigerOYxk7DQ9zNeaFUzFt8Pz-SCPItEcFXXIrCOm3IlyDh-yYZsMmSQhdIGneGF7DCr2NnpbF4k25VAne516t9ogCCdxvvFkqVVh2oi_lxZtXEnELqz3SsCzV5fKvxQSo8NycSe3kjBHFmLGwSILzUMeSzYjpbC7SEnYVFpVfz0LmxfDTkLWL8-uE55Qxo7BFkbRIuqUdlpEYrb7lMPKpP7BvCcIy6lXg7tyX1g-wPmsiFJlojXTWU-xWEafEwXLJ7l-YTBMQDyEYSgDBT9f-Motj6ZtwIsB0aG6tHLoXWdFqOQ",
        "q": "_UCFtRnO9UbmxyVLX9Sq2_qI5WhXTTH2G5KWn-tA-j7xuvurqcx6IKm8yxDHKk1iDgORSkFUcOjP5B249jPR8_MpWl9VPbkpc-Kp41hqsI_8tqaTm-nmwG8KGukOnVX98BJ6EyGWlEYDlXPsEU58H1r3M9B6AbXwShCB1qomBf0",
        "e": "AQAB",
        "kty": "RSA",
        "kid": "Jb8ZVEFoN1OZjdMoO6H7csDR8UPRtwgmXV6i2uzbGkY",
        "d": "ESgxk5qlzQYhto4zE3q8ueI1MCG4ltfi70Tex5RkYnHoYXQ0lgQYMrQbgD89gyIKyR-3lPim30yudFqF5583uDMZdaeaEn9P3f0QvPea6di1iYuPxf1AmUoFcRw3h309md3tFuRQpGMdzZDiTHvj6eCPo7IEJMxXUNrGnSIg6GBSf1N4-eV9-hBw0zUNi6qY4DdnK4g9qWkn2xSRORxH7ihUWffakyE_ZWlvxFP70cbYeGE-N9gD9DnIcgGvy-A1cXSXqqaPytzVa9cUzwPV6h5goA86Iq135yKCEeRkvl8r_jU20JQJvXyfQFJC9WHl8coPTI9PQCJFDNjlv5z_uQ",
        "p": "0fXOmXOEAgSMtP6GxgbN-cVYDMQ9_ExyM28Gp_pBwy0EOfpYkhITnaqvdN3H-TTTgZ1XkAlNmC0TqztF6Mmd3mNGWBgUN8vEGpRMinnqXNrUgh5_tWr2crsdqmTRegrZVCyVUm_CQSvQHft8i8yidqzDud5XModLSEC8olyMC-0"
      },
      {
        "use": "sig",
        "n": "sTmvermNFgmCErMP-Eo5a1CWlR69N_eEcEWMlSW2JTwyQK7Ao5ulcNs730O2M6BTrZOqH146heN9XQoYQVfdzgVTuuA9ivRfdazAh7SpMPCp4WtxG-eVuaWNDPKWFf8NHkU83Wpq3UyYtAWxE-Cm3KPlY5HlU3MAr9rv5uLUm7bHjHBl2PaVMfGrNquSImocD7N9pvgoUjM6hHfhCS9MGn3ulYBeWueMlMR3mwQTgNnKcYY4lChgQz8cB2pUADWIAfM1Rour_Xwv_aHlnhM1BvP0mG65WeB8NcCqYZYPDpp48og6SjmNLfSiVaUubChJ9Bv0mpQUxRX5a_hKph64Dw",
        "q": "5uWOdbicks_BIImjfx2Q0eXkxnCVWpCyuVDFQbP5xHkN3SWgv9146U9zDdc414RT4SaGuC3H7whO0ph48izuwUkqVZATkGLYPjRj3z0QMRUm_WTKJNDyGoK2weA82xVcUsCfWX_n7QE6GLa5RR4eOL_pqe1MFTJpzOuYXU5bbN0",
        "e": "AQAB",
        "kty": "RSA",
        "kid": "QTxQZYpSX_HLmP_piD3k8aP8bq0vfwy3wXTnfrz8Qlc",
        "d": "GoeSm7H8C0D4Hjl82gOubcCeEguMcrzUMARRQ6BmEFPfB-zA_JzXmrnO0CCwPTEyZYj1zgVKiHFh-lQBBoMTOnx0qMRZohvr0E9AcPAb5a4ZGBv_zhgQQz6jiz0jN367JX1i25hLD_6f208Az4NxJxVHyOx1olTUVP7Wq77n6bkmUnI0VKbdVO6MDmwDjdsynt2kRGEsRdPNvDhUsBxwesqjSrrawwLGILGYveno-i2saFHihFFpBO58OVnJXzowSne_9SKI01PH2PYHrmc-rE6lxmwIysbguS9H0YvygWxx0es3_G3gqjrRZsSqXNuVxyfJSAESKQQMnhIE1m-N3Q",
        "p": "xH5RaAwfjt5ZsWn626mxtHh5vEmKdqBY0DcnTmpUSvfLXtzhIf8lnyy-hBFbFUKH2mSng-QqyIHjsTPQAGAD-VCgoATleIsPKYSDOUqB2H7v-CBTLEDQiuaj9PuiIsEuGEBCuVGLR2yvy9iquVED9SILynro4S8DIVfLUkcKA9s"
      },
      {
        "y": "CK7MZC1WqmrX9NFVkqp2ONXri-7ex-zRR0TNrnZ1XGo",
        "use": "sig",
        "crv": "P-256",
        "kty": "EC",
        "kid": "dat3aVDlZO57WjObkuvdk1ipku6g4pNOWJ6_vnVoX1A",
        "d": "H5evN3jPEtSURbpzlp23RJ0gTMSg-fUxMdWczA9u38U",
        "x": "FZCtFh6QmoHZ8vmQiDFOVIOEBqr9Lokqw_yLFB8oq3Y"
      }
    ]
  };

  var kb = new KeyBundle();
  kb.imp_jwks = jwk;
  console.log(kb.getKty('EC'));*/

  /*var jwk = {"keys": [
    {
        "n":
            "zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
        "e": "AQAB", "kty": "RSA", "kid": "rsa1"},
    {
        "n":
            "zkpUgEgXICI54blf6iWiD2RbMDCOO1jV0VSff1MFFnujM4othfMsad7H1kRo50YM5S_X9TdvrpdOfpz5aBaKFhT6Ziv0nhtcekq1eRl8mjBlvGKCE5XGk-0LFSDwvqgkJoFYInq7bu0a4JEzKs5AyJY75YlGh879k1Uu2Sv3ZZOunfV1O1Orta-NvS-aG_jN5cstVbCGWE20H0vFVrJKNx0Zf-u-aA-syM4uX7wdWgQ-owoEMHge0GmGgzso2lwOYf_4znanLwEuO3p5aabEaFoKNR4K6GjQcjBcYmDEE4CtfRU9AEmhcD1kleiTB9TjPWkgDmT9MXsGxBHf3AKT5w",
        "e": "AQAB", "kty": "RSA", "kid": "rsa1"},
]}

  var kb = new KeyBundle();  
  kb.imp_jwks = jwk;  */


  //console.log(kb.getKeys());

/*
  var originalKbKeys = kb.getKeys();
  var kbKeysList = kb.getKeys();
  for (var i = originalKbKeys.length-1; i >= 1; i--){
    kb.remove(kbKeysList[i]);
  }
  console.log(kb.getKeys());

  for (var i in kb.getKeys()){
    kb.markAsInactive(kb.keys[i].kid)    
  }

  console.log(kb.getKeys());*/

  //kb.doLocalJwk("/Users/anjuthomas/Documents/jwk.json");

/*
  var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jwtid");
  basicIdToken.addNonStandardClaims({"foo": 'bar', "aud" : "audience"});
  basicIdToken.setNoneAlgorithm(true);
  var token = basicIdToken.toJWT("shh", {algorithm: 'HS256'});

  var HttpClient = function() {
    this.get = function(aUrl, aCallback) {
        var anHttpRequest = new XMLHttpRequest();
        anHttpRequest.onreadystatechange = function() { 
            if (anHttpRequest.readyState == 4 && anHttpRequest.status == 200)
                aCallback(anHttpRequest.responseText);
        }

        anHttpRequest.open( "GET", aUrl, true );            
        anHttpRequest.send( null );
    }
  }

  var client = new HttpClient();
  client.get('https://sandrino.auth0.com/.well-known/jwks.json', function(response) {
    // do something with response
    console.log(response);
    jwtDecoder.verifyJwtSignature(token, "test", basicIdToken,  {"clockTimestamp" : clockTimestamp, jwtid: 'jwtid' }, response, "base64");
  });

  /*

  function b64_to_utf8 (str) {
    return decodeURIComponent(escape(atob( str )));
  }

  var urlEncodedVal = basicIdToken.toUrlEncoded();

  var decodedVal = basicIdToken.fromUrlEncoded(urlEncodedVal);

  var jsonStr = basicIdToken.toJSON();
  
  var decodedJson = basicIdToken.fromJSON(jsonStr);
*/


  /*
  try{
    var decoded = basicIdToken.fromJWT(token, "shh", {"foo": "bar","aud" : "audience", "iss" : "issuer", "sub": "subject", 'maxAge': '3s', 'clockTolerance' : 10, "jti": "jwtid"}, {"clockTimestamp" : clockTimestamp, jwtid: 'jwtid' });
  }catch(err){
    assert.isNotNull(decoded);
    assert.isNull(err);
  }*/
  /*
  var certs = {
    "use": "enc",
    "n": "z7TYSonR4KTijDVTJJHBRs_7MUtvy2_aIPOKpkbigerOYxk7DQ9zNeaFUzFt8Pz-SCPItEcFXXIrCOm3IlyDh-yYZsMmSQhdIGneGF7DCr2NnpbF4k25VAne516t9ogCCdxvvFkqVVh2oi_lxZtXEnELqz3SsCzV5fKvxQSo8NycSe3kjBHFmLGwSILzUMeSzYjpbC7SEnYVFpVfz0LmxfDTkLWL8-uE55Qxo7BFkbRIuqUdlpEYrb7lMPKpP7BvCcIy6lXg7tyX1g-wPmsiFJlojXTWU-xWEafEwXLJ7l-YTBMQDyEYSgDBT9f-Motj6ZtwIsB0aG6tHLoXWdFqOQ",
    "q": "_UCFtRnO9UbmxyVLX9Sq2_qI5WhXTTH2G5KWn-tA-j7xuvurqcx6IKm8yxDHKk1iDgORSkFUcOjP5B249jPR8_MpWl9VPbkpc-Kp41hqsI_8tqaTm-nmwG8KGukOnVX98BJ6EyGWlEYDlXPsEU58H1r3M9B6AbXwShCB1qomBf0",
    "e": "AQAB",
    "kty": "RSA",
    "kid": "Jb8ZVEFoN1OZjdMoO6H7csDR8UPRtwgmXV6i2uzbGkY",
    "d": "ESgxk5qlzQYhto4zE3q8ueI1MCG4ltfi70Tex5RkYnHoYXQ0lgQYMrQbgD89gyIKyR-3lPim30yudFqF5583uDMZdaeaEn9P3f0QvPea6di1iYuPxf1AmUoFcRw3h309md3tFuRQpGMdzZDiTHvj6eCPo7IEJMxXUNrGnSIg6GBSf1N4-eV9-hBw0zUNi6qY4DdnK4g9qWkn2xSRORxH7ihUWffakyE_ZWlvxFP70cbYeGE-N9gD9DnIcgGvy-A1cXSXqqaPytzVa9cUzwPV6h5goA86Iq135yKCEeRkvl8r_jU20JQJvXyfQFJC9WHl8coPTI9PQCJFDNjlv5z_uQ",
    "p": "0fXOmXOEAgSMtP6GxgbN-cVYDMQ9_ExyM28Gp_pBwy0EOfpYkhITnaqvdN3H-TTTgZ1XkAlNmC0TqztF6Mmd3mNGWBgUN8vEGpRMinnqXNrUgh5_tWr2crsdqmTRegrZVCyVUm_CQSvQHft8i8yidqzDud5XModLSEC8olyMC-0"
  };*/

    
  /*
  var clockTimestamp = 1511783267;
  
  var basicIdToken = new BasicIdToken('issuer','subject', clockTimestamp, "jti");
  basicIdToken.addNonStandardClaims({"foo": 'bar', "aud": 'urn:foo'});
  basicIdToken.setNoneAlgorithm(true);
  var token = basicIdToken.toJWT("shh", {algorithm: 'HS256'});

  try{
    var decoded = basicIdToken.fromJWT(token, "shh", {"foo": "bar", "aud" :  /urn:f[o]{2}/ , "iss" : "issuer", "sub": "subject", 'maxAge': '3s', 'clockTolerance' : 10, "jti": "jti"}, {"clockTimestamp" : clockTimestamp});
  }catch(err){
    console.log(err);
    assert.isUndefined(decoded);
    assert.isNotNull(err);
    assert.equal(err.name, 'JsonWebTokenError');
  } 

  try{
    var decoded = basicIdToken.fromJWT(token, "shh", {"foo": "bar","aud" : 'urn:wrong', "iss" : "issuer", "sub": "subject", 'maxAge': '3s', 'clockTolerance' : 10, "jti": "jti"}, {"clockTimestamp" : clockTimestamp });
  }catch(err){
    console.log(err);
    assert.isUndefined(decoded);
    assert.isNotNull(err);
    assert.equal(err.name, 'JsonWebTokenError');
  } */
