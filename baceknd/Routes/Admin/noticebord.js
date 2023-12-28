const express = require("express");
const router = express.Router();
const data = require("../../controller/Admin/noticebord");
const auth = require("../../middleware/Auth");
const singeupload = require("../../middleware/multer2")
// Create a new notice
router.route("/add-notice").post(auth.isAuthenticateUser,singeupload ,data.createNotice);
// Get all notices
router.get("/notices",
 auth.isAuthenticateUser, 
 data.getAllNotices);

router.get("/notices/like/:id", auth.isAuthenticateUser, data.LikeNotice);

// Get a notice by ID 
router
  .route("/notices/:id")
  .get(auth.isAuthenticateUser, data.getNoticeById) 
  .put(auth.isAuthenticateUser, data.updateNotice)
  .delete(auth.isAuthenticateUser, data.deleteNotice);

module.exports = router;
