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

var mutableMapping = require('./MutableMapping');
var DecodeError = require('./lib/DecodeError');
var InvalidAlgorithmException = require('./lib/InvalidAlgorithmException');
var KeyError = require('./lib/KeyError');
var MissingRequiredAttributeError = require('./lib/MissingRequiredAttributeError');
var NotAllowedValueError = require('./lib/NotAllowedValueError');
var ParameterError = require('./lib/ParameterError');
var TooManyValuesError = require('./lib/TooManyValuesError');
var TypeError = require('./lib/TypeError');
var UnicodeEncodeError = require('./lib/UnicodeEncodeError');
var KeyIOError = require('./lib/KeyIOError');
var MessageException = require('./lib/MessageException');
var NoSuitableSigningKeysError = require('./lib/NoSuitableSigningKeysError');

var message = Message.prototype;
message = Object.create(mutableMapping);
message.constructor = Message;

function Message(kwargs){
};

message.c_param = {};
message.c_default = {};
message.c_allowed_values = {};

message.parameters = function(){
    /**  Returns a list of all known parameters for this message type.
        :return: list of parameter names  */
    throw new Error("Unsupported Operation Exception");         
};

message.setDefaults = function(){
    /** Based on specification set a parameters value to the default value. */
    throw new Error("Unsupported Operation Exception");    
};

message.toUrlEncoded = function(level){
    /**  Creates a string using the application/x-www-form-urlencoded format
        :return: A string of the application/x-www-form-urlencoded format */
    try{
        throw new Error("Unsupported Operation Exception"); 
    } catch (e){
        if (e instanceof MissingRequiredAttributeError){
            // Statements to handle error
        } else if (e instanceof InvalidKeyException){
            // Statements to handle error
        } else if (e instanceof InvalidValueError){
            // Statements to handle error
        } else if (e instanceof TypeError){
            // Statements to handle error
        } else if (e instanceof UnicodeEncodeError){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }
};

message.fromUrlEncoded = function(urlEncoded, kwargs){
    /**  Starting with a string of the application/x-www-form-urlencoded format 
        this method creates a class instance
        :param urlencoded: The string
        :return: A class instance or raise an exception on error */
    try{
        throw new Error("Unsupported Operation Exception");   
    } catch (e){
        if (e instanceof InvalidKeyException){
            // Statements to handle error
        } else if (e instanceof InvalidValueError){
            // Statements to handle error
        } else if (e instanceof ParameterError){
            // Statements to handle error
        } else if (e instanceof TooManyValuesError){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }
};

message.serialize = function(method="urlencoded", lev=0, kwargs){
    /** Convert this instance to another representation. Which representation 
        is given by the choice of serialization method.
        
        :param method: A serialization method. Presently 'urlencoded', 'json',
            'jwt' and 'dict' is supported.
        :param lev: 
        :param kwargs: Extra key word arguments
        :return: THe content of this message serialized using a chosen method */
    throw new Error("Unsupported Operation Exception");    
};

message.deserialize = function(info, method="urlencoded", kwargs){
    /**  Convert from an external representation to an internal.
        
        :param info: The input  
        :param method: The method used to deserialize the info
        :param kwargs: extra Keyword arguments
        :return: In the normal case the Message instance */
    throw new Error("Unsupported Operation Exception");    
}

message.toDict = function(lev){
    /** Return a dictionary representation of the class
        :return: A dict */
    try{
        throw new Error("Unsupported Operation Exception"); 
    } catch (e){
        if (e instanceof InvalidKeyException){
            // Statements to handle error
        } else if (e instanceof InvalidValueError){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }
};

message.fromDict = function(dictionary, kwargs){
    /**   Direct translation, so the value for one key might be a list or a
        single value.
        :param dictionary: The info
        :return: A class instance or raise an exception on error*/
    try{
        throw new Error("Unsupported Operation Exception");    
    } catch (e){
        if (e instanceof InvalidKeyException){
            // Statements to handle error
        } else if (e instanceof InvalidValueError){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }
};

message.addValue = function(sKey, vTyp, key, val,_deser, isNullAllowed){
    /**   Main method for adding a value to the instance. Does all the
        checking on type of value and if among allowed values.
        :param sKey: string version of the key 
        :param vTyp: Type of value
        :param key: original representation of the key
        :param val: The value to add
        :param _deser: A deserializer for this value type
        :param isNullAllowed: Whether null is an allowed value for this key */
    try{
        throw new Error("Unsupported Operation Exception");    
    } catch (e){
        if (e instanceof DecodeError){
            // Statements to handle error
        } else if (e instanceof InvalidValue){
            // Statements to handle error
        } else if (e instanceof IllegalArgumentException){
            // Statements to handle error
        } else if (e instanceof TooManyValues){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }
};

message.toJson = function(lev, indent){
    /** Serialize the content of this instance into a JSON string.
        
        :param lev: 
        :param indent: Number of spaces that should be used for indentation 
        :return:  */
    throw new Error("Unsupported Operation Exception");        
};

message.fromJson = function(txt){
    /** Convert from a JSON string to an instance of this class.
        
        :param txt: The JSON string 
        :param kwargs: extra keyword arguments
        :return: The instantiated instance  */
    throw new Error("Unsupported Operation Exception");        
};

message.toJwt = function(key=None, algorithm="", lev=0){
    /**  Create a signed JWT representation of the class instance
        :param key: The signing key
        :param algorithm: The signature algorithm to use
        :param lev:
        :param lifetime: The lifetime of the JWS
        :return: A signed JWT */
    throw new Error("Unsupported Operation Exception");        
};

message.fromJwt = function(txt, key=None, verify=True, keyjar=None, kwargs){
    /** Given a signed and/or encrypted JWT, verify its correctness and then
        create a class instance from the content.
        :param txt: The JWT
        :param key: keys that might be used to decrypt and/or verify the
            signature of the JWT
        :param verify: Whether the signature should be verified or not
        :param keyjar: A KeyJar that might contain the necessary key.
        :param kwargs: Extra key word arguments
        :return: A class instance */
    try{
        throw new Error("Unsupported Operation Exception");   
    } catch (e){
        if (e instanceof AssertionError){
            // Statements to handle error
        } else if (e instanceof InvalidAlgorithmException){
            // Statements to handle error
        } else if (e instanceof InvalidSignatureValueException){
            // Statements to handle error
        } else if (e instanceof InvalidKeyException){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }    
};

message.addKey = function(keyjar, issuer, key, keyType="", kid="", noKidIssuer=None){
    try{
        throw new Error("Unsupported Operation Exception");  
    }catch (e){
        if (e instanceof KeyError){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }       
};

message.getVerifyKeys = function(keyjar, key, jso, header, jwt, kwargs){
    try{ 
        throw new Error("Unsupported Operation Exception");  
    }catch (e){
        if (e instanceof KeyError){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }    
};

message.typeCheck = function(type, allowed, val, na){
    try{
        throw new Error("Unsupported Operation Exception");  
    } catch (e){
        if (e instanceof NotAllowedValueError){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }
};

message.verify = function(kwargs){
    /** Make sure all the required values are there and that the values are
        of the correct type */
    try{
        throw new Error("Unsupported Operation Exception");
    } catch (e){
        if (e instanceof KeyError){
            // Statements to handle error
        } else if (e instanceof MissingRequiredAttributeError){
            // Statements to handle error
        } else if (e instanceof InvalidValueError){
            // Statements to handle error
        } else if (e instanceof NotAllowedValueError){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }       
};

message.getKeys= function(){
    /** Return a list of attribute/keys/parameters of this class that has
        values. */
    throw new Error("Unsupported Operation Exception");        
};

message.getItem = function(item){
    /** Return the value of a specified parameter. */
    throw new Error("Unsupported Operation Exception");        
};

message.get = function(item, defaultValue){
    /**   Return the value of a specific parameter. If the parameter does not
        have a value return the default value.

        :param item: The name of the parameter 
        :param default: Default value
        :return: The value of the parameter or, if that doesn't exist, 
        the default value  */
    try{
        throw new Error("Unsupported Operation Exception");    
    } catch (e){
        if (e instanceof KeyError){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }
};

message.getItems = function(){
    /**  Return a list of tuples (key, value) representing all parameters
        of this class instance that has a value.
        
        :return: iterator  */
    throw new Error("Unsupported Operation Exception");        
};

message.getValues = function(){
    throw new Error("Unsupported Operation Exception");        
};

message.request = function(location, fragmentEnc){
    /** Given a URL this method will add a fragment, a query part or extend
        a query part if it already exists with the information in this instance.
        
        :param location: A URL 
        :param fragmentEnc: Whether the information should be placed in a
            fragment (True) or in a query part (False)
        :return: The extended URL  */
    throw new Error("Unsupported Operation Exception");        
};

message.setItem = function(key, value){
    try{
        throw new Error("Unsupported Operation Exception"); 
    } catch (e){
    if (e instanceof KeyError){
        // Statements to handle error
    } else {
        // statements to handle error
    }      
};

message.equals = function(other){
    /** Compare two message instances. This with another instance.
        
        :param other:  The other instance
        :return: True/False */
    throw new Error("Unsupported Operation Exception");        
};

message.deleteItem = function(key){
    throw new Error("Unsupported Operation Exception");            
};

message.getLength = function(){
    /** Return the number of parameters that has a value.
        
        :return: Number of parameters with a value. */
    throw new Error("Unsupported Operation Exception");            
};

message.extra = function(){
    /**  Return the extra parameters that this instance. Extra meaning those
        that are not listed in the c_params specification.
        
        :return: The key,value pairs for keys that are not in the c_params
            specification. */
    throw new Error("Unsupported Operation Exception");            
};

message.onlyExtras = function(){
    /** Return True if this instance only has key,value pairs for keys
        that are not defined in c_params.
        
        :return: True/False */
    throw new Error("Unsupported Operation Exception");            
};

message.update = function(item){
    /**  Update the information in this instance.
        
        :param item: a dictionary or a Message instance  */
    try{
        throw new Error("Unsupported Operation Exception"); 
    } catch (e){
        if (e instanceof InvalidValue){
            // Statements to handle error
        } else {
            // statements to handle error
        }
    }        
};

message.toJWE = function(keys, enc, alg, lev){
    /** Place the information in this instance in a JSON object. Make that
        JSON object the body of a JWT. Then encrypt that JWT using the
        specified algorithms and the given keys. Return the encrypted JWT.
        :param keys: Dictionary, keys are key type and key is the value or
            simple list.
        :param enc: Content Encryption Algorithm
        :param alg: Key Management Algorithm
        :param lev: Used for JSON construction
        :return: An encrypted JWT. If encryption failed an exception will be
            raised. */
    throw new Error("Unsupported Operation Exception");            
};

message.fromJWE = function(msg, keys){
    /** Decrypt an encrypted JWT and load the JSON object that was the body
        of the JWT into this object.
        :param msg: An encrypted JWT
        :param keys: Dictionary, keys are key type and key is the value or
            simple list.
        :return: The decrypted message. If decryption failed an exception
            will be raised. */
    throw new Error("Unsupported Operation Exception");            
};

message.weed = function(){
    /** Get rid of key value pairs that are not standard */
    throw new Error("Unsupported Operation Exception");            
};

message.removeBlanks = function(){
    /** Get rid of parameters that has no value. */
    throw new Error("Unsupported Operation Exception");            
};

module.exports = message;
