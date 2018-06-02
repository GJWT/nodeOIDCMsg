const Message = require('../message');
const AccessToken = require('../tokenProfiles/accessToken');
const SINGLE_REQUIRED_STRING = require('./init').SINGLE_REQUIRED_STRING
const SINGLE_OPTIONAL_STRING = require('./init').SINGLE_OPTIONAL_STRING
const REQUIRED_LIST_OF_SP_SEP_STRINGS =
    require('./init').REQUIRED_LIST_OF_SP_SEP_STRINGS;
const OPTIONAL_LIST_OF_SP_SEP_STRINGS =
    require('./init').OPTIONAL_LIST_OF_SP_SEP_STRINGS;

/**
 * @fileoverview Contains all the OIC request classes
 */

/**
 * AccessTokenRequest
 * @class
 * @constructor
 * @extends Message
 * An access token request
 */
class AccessTokenRequest extends Message {
  constructor(args) {
    super(args);
    if (args){
      this.claims = args;
    }else{
      this.claims = {};
    }
    this.cParam = {
      'grant_type': SINGLE_REQUIRED_STRING,
      'code': SINGLE_REQUIRED_STRING,
      'redirect_uri': SINGLE_REQUIRED_STRING,
      'client_id': SINGLE_OPTIONAL_STRING,
      'client_secret': SINGLE_OPTIONAL_STRING,
      'state': SINGLE_OPTIONAL_STRING
    };
    this.cDefault = {'grant_type': 'authorization_code'};
    return this;
  }
}

/**
 * AuthorizationRequest
 * @class
 * @constructor
 * @extends Message
 * An authorization request
 */
class AuthorizationRequest extends Message {
  constructor(reqArgs) {
    super(reqArgs);
    if (reqArgs){
      this.claims = reqArgs;
    }else{
      this.claims = {};
    }
    this.cParam = {
      'response_type': REQUIRED_LIST_OF_SP_SEP_STRINGS,
      'client_id': SINGLE_REQUIRED_STRING,
      'scope': OPTIONAL_LIST_OF_SP_SEP_STRINGS,
      'redirect_uri': SINGLE_OPTIONAL_STRING,
      'state': SINGLE_OPTIONAL_STRING,
    };
    return this;
  }
};

/**
 * ROPCAccessTokenRequest
 * @class
 * @constructor
 * @extends Message
 * Resource Owner Password Credentials Grant flow access token request
 */
class ROPCAccessTokenRequest extends Message {
  constructor() {
    super();
    this.cParam = {
      'grant_type': SINGLE_REQUIRED_STRING,
      'username': SINGLE_OPTIONAL_STRING,
      'password': SINGLE_OPTIONAL_STRING,
      'scope': OPTIONAL_LIST_OF_SP_SEP_STRINGS
    }
  }
};

/**
 * CCAccessTokenRequest
 * @class
 * @constructor
 * @extends Message
 * Client Credential grant flow access token request
 */
class CCAccessTokenRequest extends Message {
  constructor(args) {
    super(args);
    this.cParam = {
      'grant_type': SINGLE_REQUIRED_STRING,
      'scope': OPTIONAL_LIST_OF_SP_SEP_STRINGS
    };
    this.cDefault = {
      'grant_type': 'client_credentials'
    };
    this.cAllowedValues = {
      'grant_type': ['client_credentials']
    };
    return args;
  }
};

/**
 * RefreshAccessTokenRequest
 * @class
 * @constructor
 * @extends Message
 */
class RefreshAccessTokenRequest extends Message {
  constructor(claims) {
    super(claims);
    this.cParam = {
      'grant_type': SINGLE_REQUIRED_STRING,
      'refresh_token': SINGLE_REQUIRED_STRING,
      'scope': OPTIONAL_LIST_OF_SP_SEP_STRINGS,
      'client_id': SINGLE_OPTIONAL_STRING,
      'client_secret': SINGLE_OPTIONAL_STRING
    };
    this.claims = {'grant_type': 'refresh_token'};
    this.cAllowedValues = {'grant_type': ['refresh_token']};
  }
}

/**
 * RefreshRequest
 * @class
 * @constructor
 * @extends Message
 */
class ResourceRequest extends Message {
  constructor(args) {
    super(args);
    if (args){
      this.claims = args;
    }else{
      this.claims = {}
    }
    this.cParam = {'access_token': SINGLE_OPTIONAL_STRING};
    return this;
  }
}

module.exports.AccessTokenRequest = AccessTokenRequest;
module.exports.AuthorizationRequest = AuthorizationRequest;
module.exports.ROPCAccessTokenRequest = ROPCAccessTokenRequest;
module.exports.CCAccessTokenRequest = CCAccessTokenRequest;
module.exports.RefreshAccessTokenRequest = RefreshAccessTokenRequest;
module.exports.ResourceRequest = ResourceRequest;