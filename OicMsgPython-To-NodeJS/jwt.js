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

