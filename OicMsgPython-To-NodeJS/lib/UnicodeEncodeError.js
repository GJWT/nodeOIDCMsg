  var UnicodeEncodeError = function (message, error) {
    Error.call(this, message);
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = 'UnicodeEncodeError';
    this.message = message;
    if (error) this.inner = error;
  };
  
  UnicodeEncodeError.prototype = Object.create(Error.prototype);
  UnicodeEncodeError.prototype.constructor = UnicodeEncodeError;
  
  module.exports = UnicodeEncodeError;