
var SINGLE_OPTIONAL_STRING = require('../OAuth2/init').SINGLE_OPTIONAL_STRING;
var SINGLE_REQUIRED_IDTOKEN = require('../OAuth2/init').SINGLE_REQUIRED_IDTOKEN;
var OPTIONAL_LIST_OF_STRINGS = require('../OAuth2/init').OPTIONAL_LIST_OF_STRINGS;
var SINGLE_OPTIONAL_DICT = require('../OAuth2/init').SINGLE_OPTIONAL_DICT;

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