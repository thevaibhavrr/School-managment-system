const multer = require("multer");
// const path = require("path");
// const fs = require("fs");

const multerStorage = multer.diskStorage({
  destination: "uploads",
  filename: (req, file, cb) => {
    cb(null, file.originalname);
  },
});

// Use diskstorage option in multer
const upload = multer({ storage: multerStorage });

module.exports = upload;


// 6 pack 
// const multer = require("multer");
// const storage = multer.memoryStorage();

// const singeupload = multer({ storage }).single("file");

// module.exports = singeupload;