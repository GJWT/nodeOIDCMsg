  var DecodeError = function (message, error) {
    Error.call(this, message);
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = 'DecodeError';
    this.message = message;
    if (error) this.inner = error;
  };
  
  DecodeError.prototype = Object.create(Error.prototype);
  DecodeError.prototype.constructor = DecodeError;
  
  module.exports = DecodeError;