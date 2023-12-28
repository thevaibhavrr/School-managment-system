// try catch

module.exports = (TheFunck) => (req, res, next) => {
   Promise.resolve(TheFunck(req, res, next)).catch(next);
};


