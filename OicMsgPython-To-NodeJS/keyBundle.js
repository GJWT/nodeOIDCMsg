'use strict';

var keyBundle = KeyBundle.prototype;

function KeyBundle(keys=None, source="", cache_time=300, verify_ssl=True, fileformat="jwk", keyType="RSA", encEnc="A128CBC-HS256", keyUsage="None"){
};

keyBundle.doKeys = function(keys){
    throw new Error("Unsupported Operation Exception");         
};

keyBundle.doLocalJwk = function(filename){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.doLocalDer = function(filename, keytype, keyUsage){
    throw new Error("Unsupported Operation Exception");
};

keyBundle.do_remote = function(){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.parseRemoteResponse = function(response){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.upToDate = function(){
    throw new Error("Unsupported Operation Exception");    
}

keyBundle.update = function(token){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.get = function(typ=""){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.keys = function(){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.availableKeys = function(){
    throw new Error("Unsupported Operation Exception");    
}

keyBundle.removeKey = function(type, val=None){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.toString = function(type, val=None){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.jwks= function(private=False){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.append = function(key){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.remove = function(key){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.length= function(){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.getKeyWithKid= function(kid){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.kids = function(){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.removeOutdated = function(after, when=0){
    throw new Error("Unsupported Operation Exception");    
};

keyBundle.keybundleFromLocalFile= function(fileName, typ, usage){
    throw new Error("Unsupported Operation Exception");    
};

module.exports = keyBundle;

