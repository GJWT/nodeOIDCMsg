'use strict';

var KeyError = require('./lib/KeyError');
var NoSuitableSigningKeysError = require('./lib/NoSuitableSigningKeysError');

var jwt = JWT.prototype;

function JWT(keyjar, iss='', lifetime=0, signAlg='RS256', msgType=JsonWebToken, encrypt=False, encEnc="A128CBC-HS256", encAlg="RSA1_5"){
};

jwt.encrypt = function(payload, cty="JWT"){
    throw new Error("Unsupported Operation Exception");         
};

jwt.packInit = function(){
    throw new Error("Unsupported Operation Exception");    
};

jwt.packKey= function(owner="", kid=""){
    try{
        throw new Error("Unsupported Operation Exception");
    } catch (e){
        if (e instanceof NoSuitableSigningKeys){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }
};

jwt.pack = function(kid="", owner="", cls_instance=None, kwargs){
    throw new Error("Unsupported Operation Exception");    
};

jwt.verify = function(rj, token){
    throw new Error("Unsupported Operation Exception");    
};

jwt.decrypt = function(rj, token){
    try{
        throw new Error("Unsupported Operation Exception");
    } catch (e){
        if (e instanceof KeyError){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }    
}

jwt.unpack = function(token){
    try { 
        throw new Error("Unsupported Operation Exception");  
    } catch (e){
        if (e instanceof KeyError){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }   
};

module.exports = jwt;

