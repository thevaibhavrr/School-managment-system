// // add error handel class in Error class
class ErrorHandler extends Error {
  //   // running ervery time when it will call
  // require data from controler msg and code
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    Error.captureStackTrace(this, this.constructor);
  }
}

module.exports = ErrorHandler;