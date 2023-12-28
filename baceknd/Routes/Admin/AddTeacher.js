const express = require("express");
const router = express.Router();
const auth = require("../../middleware/Auth");
const Data = require("../../controller/UserController/User");
const singeupload = require("../../middleware/multer2");

// add a teacher
router.post(
  "/addteacher",
  auth.isAuthenticateUser,
  auth.authorizeRole("admin"),
  singeupload,
  Data.AddUser
);

// get all teachers
router.get(
  "/allteacher",
  auth.isAuthenticateUser, 
  auth.authorizeRole("admin"),
  Data.AllUser
);

// get a single teacher by ID
router.get(
  "/singleteacher/:id",
  auth.isAuthenticateUser,
  auth.authorizeRole("admin"),
  Data.UserbyId
);

// update a teacher
router.put(
  "/updateteacher/:id",
  auth.isAuthenticateUser,
  auth.authorizeRole("admin"),
  Data.UpdateUser
);

// delete a teacher
router.delete(
  "/deleteteacher/:id",
  auth.isAuthenticateUser,
  auth.authorizeRole("admin"),
  Data.DeleteUser
);

module.exports = router;



