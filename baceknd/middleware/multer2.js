// const multer = require("multer");

// const storage = multer.memoryStorage();

// const singelupload = multer({storage}).single("file")

// module.exports = singelupload
















const multer = require("multer") 
const storage = multer.memoryStorage()

const singelupload = multer({storage}).single("file")

module.exports = singelupload;