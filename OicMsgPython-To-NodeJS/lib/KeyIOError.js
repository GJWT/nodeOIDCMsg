var KeyIOError = function (message, error) {
    Error.call(this, message);
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = 'KeyIOError';
    this.message = message;
    if (error) this.inner = error;
  };
  
  KeyIOError.prototype = Object.create(Error.prototype);
  KeyIOError.prototype.constructor = KeyIOError;
  
  module.exports = KeyIOError;