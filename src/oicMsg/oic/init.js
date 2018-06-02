
var SINGLE_OPTIONAL_STRING = require('../OAuth2/init').SINGLE_OPTIONAL_STRING;
var SINGLE_OPTIONAL_BOOLEAN = require('../OAuth2/init').SINGLE_OPTIONAL_BOOLEAN;
var SINGLE_REQUIRED_IDTOKEN = require('../OAuth2/init').SINGLE_REQUIRED_IDTOKEN;
var SINGLE_REQUIRED_STRING = require('../OAuth2/init').SINGLE_REQUIRED_STRING;
var OPTIONAL_LIST_OF_STRINGS = require('../OAuth2/init').OPTIONAL_LIST_OF_STRINGS;
var SINGLE_OPTIONAL_DICT = require('../OAuth2/init').SINGLE_OPTIONAL_DICT;
var SINGLE_OPTIONAL_INT = require('../OAuth2/init').SINGLE_OPTIONAL_INT;
var OPTIONAL_ADDRESS = require('../OAuth2/init').OPTIONAL_ADDRESS;
var OPTIONAL_MESSAGE = require('../OAuth2/init').OPTIONAL_MESSAGE;
var ResponseMessage = require('../oauth2/responses').ResponseMessage;

var Message = require('../message');

class AddressClaim extends Message {
  constructor() {
    super();
    this.cParam = {
      'formatted': SINGLE_OPTIONAL_STRING,
      'street_address': SINGLE_OPTIONAL_STRING,
      'locality': SINGLE_OPTIONAL_STRING,
      'region': SINGLE_OPTIONAL_STRING,
      'postal_code': SINGLE_OPTIONAL_STRING,
      'country': SINGLE_OPTIONAL_STRING
    };
  }
}

class OpenIDSchema extends ResponseMessage{
  constructor(claims){
    super(claims);
    if (claims){
      this.claims = claims;
    }else{
      this.claims = {};
    }
    this.cParam = {
      "sub": SINGLE_REQUIRED_STRING,
      "name": SINGLE_OPTIONAL_STRING,
      "given_name": SINGLE_OPTIONAL_STRING,
      "family_name": SINGLE_OPTIONAL_STRING,
      "middle_name": SINGLE_OPTIONAL_STRING,
      "nickname": SINGLE_OPTIONAL_STRING,
      "preferred_username": SINGLE_OPTIONAL_STRING,
      "profile": SINGLE_OPTIONAL_STRING,
      "picture": SINGLE_OPTIONAL_STRING,
      "website": SINGLE_OPTIONAL_STRING,
      "email": SINGLE_OPTIONAL_STRING,
      "email_verified": SINGLE_OPTIONAL_BOOLEAN,
      "gender": SINGLE_OPTIONAL_STRING,
      "birthdate": SINGLE_OPTIONAL_STRING,
      "zoneinfo": SINGLE_OPTIONAL_STRING,
      "locale": SINGLE_OPTIONAL_STRING,
      "phone_number": SINGLE_OPTIONAL_STRING,
      "phone_number_verified": SINGLE_OPTIONAL_BOOLEAN,
      "address": OPTIONAL_ADDRESS,
      "updated_at": SINGLE_OPTIONAL_INT,
      "_claim_names": OPTIONAL_MESSAGE,
      "_claim_sources": OPTIONAL_MESSAGE
    };
    return this;
  }
}

class MessageWithIdToken extends Message {
  constructor() {
    super();
    this.cParam = {'id_token': SINGLE_REQUIRED_IDTOKEN};
  }

  verify() {}
}

class LINK extends Message {
  constructor(dict) {
    super();
    this.cParam = {
      'rel': {'type': String, 'required': true},
      'type': {'type': String, 'required': false},
      'href': {'type': String, 'required': false},
      'titles': {'type': String, 'required': false},
      'properties': {'type': String, 'required': false},
    };
    return dict;
  }
}

let REQUIRED_LINKS = [[LINK], true, this.msgSer, this.linkDeser, false];

function linkDeser(val, sformat) {
  sformat = sformat || 'urlencoded';
  let sformats = ['dict', 'json'];
  if (val instanceof lINK) {
    return val;
  } else if (sformats.indexOf(sformat) !== -1) {
    if (!(val instanceof String)) {
      val = JSON.dumps(val);
      sformat = 'json';
    }
  }
  return LINK().deserialize(val, sformat);
}

function msgSer(inst, sformat, lev = 0) {
  let formats = ['urlencoded', 'json'];
  let res;
  if (formats.indexOf(sformat) !== -1) {
    if (inst instanceof Object) {
      if (sformat === 'json') {
        res = JSON.dumps(inst);
      } else {
        for (let i = 0; i < Object.keys(inst).length; i++) {
          let key = Object.keys(inst)[i];
          let val = inst[key];
          //res = urlencode([(key, val)]);
        }
      }
    } else if (inst instanceof LINK) {
      res = inst.serialize(sformat, lev);
    } else {
      res = inst;
    }
  } else if (sformat === 'dict') {
    if (typeof inst === LINK) {
      res = inst.serialize(sformat, lev);
    } else if (typeof inst === Object) {
      res = inst;
    } else if (typeof inst === String) {
      res = inst;
    } else {
      throw new Error('Wrong type');
    }
  } else {
    throw new Error('Unknown sformat');
  }
  return res;
}

/** JSON Resource Descriptor https://tools.ietf.org/html/rfc7033#section-4.4 **/
class JRD extends Message {
  constructor(dict) {
    super();
    this.claim = {
      'subject': SINGLE_OPTIONAL_STRING,
      'aliases': OPTIONAL_LIST_OF_STRINGS,
      'properties': SINGLE_OPTIONAL_DICT,
      'links': REQUIRED_LINKS
    };
    return dict;
  }
}

module.exports.MessageWithIdToken = MessageWithIdToken;
module.exports.OpenIDSchema = OpenIDSchema;