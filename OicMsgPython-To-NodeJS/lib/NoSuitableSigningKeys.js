var NoSuitableSigningKeysError = function (message, error) {
    Error.call(this, message);
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = 'NoSuitableSigningKeysError';
    this.message = message;
    if (error) this.inner = error;
  };
  
  NoSuitableSigningKeysError.prototype = Object.create(Error.prototype);
  NoSuitableSigningKeysError.prototype.constructor = NoSuitableSigningKeysError;
  
  module.exports = NoSuitableSigningKeysError; 