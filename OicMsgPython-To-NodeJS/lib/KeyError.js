  var KeyError = function (message, error) {
    Error.call(this, message);
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = 'KeyError';
    this.message = message;
    if (error) this.inner = error;
  };
  
  KeyError.prototype = Object.create(Error.prototype);
  KeyError.prototype.constructor = KeyError;
  
  module.exports = KeyError;