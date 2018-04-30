
var Type = {
  JSONWebTokenError: 'JSONWebTokenError',
  TokenExpiredError: 'TokenExpiredError',
  NotBeforeError: 'NotBeforeError',
};

const JSError = function(message, type, error) {

  Error.call(this, message);
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, this.constructor);
  }
  switch (type) {
    case Type.JSONWebTokenError:
      this.name = Type.JSONWebTokenError;
      break;
    case Type.TokenExpiredError:
      this.name = Type.TokenExpiredError;
      break;
    default:
      this.name = 'Unknown Error';
      break;
  }
  this.message = message;
  if (error) this.inner = error;
};

JSError.prototype = Object.create(JSError.prototype);
JSError.prototype.constructor = JSError;
module.exports = JSError;