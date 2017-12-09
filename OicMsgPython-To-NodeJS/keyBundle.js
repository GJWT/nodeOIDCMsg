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

