var MessageException = function (message, error) {
    Error.call(this, message);
    if(Error.captureStackTrace) {
      Error.captureStackTrace(this, this.constructor);
    }
    this.name = 'MessageException';
    this.message = message;
    if (error) this.inner = error;
  };
  
  MessageException.prototype = Object.create(Error.prototype);
  MessageException.prototype.constructor = MessageException;
  
  module.exports = MessageException; 