const express = require("express");
const router = express.Router();
const auth = require("../../middleware/Auth");
const Data = require("../../controller/UserController/User");
const singeupload = require("../../middleware/multer2");

// Routes for managing students

// add a new student
router.post(
  "/createstudent",
  auth.isAuthenticateUser,
  auth.authorizeRole("teacher", "admin"),
  singeupload,
  Data.AddUser
);

// get all student list
router.get(
  "/allstudent",
  auth.isAuthenticateUser,
  auth.authorizeRole("teacher", "admin"),
  Data.AllUser
);

// get a single student by ID
router.get(
  "/singlestudent/:id",
  auth.isAuthenticateUser,
  auth.authorizeRole("teacher", "admin"),
  Data.UserbyId
);

// update a student by ID
router.put(
  "/updatestudent/:id",
  auth.isAuthenticateUser,
  auth.authorizeRole("teacher", "admin"),
  Data.UpdateUser
);

// delete a student by ID
router.delete(
  "/deletestudent/:id",
  auth.isAuthenticateUser,
  auth.authorizeRole("teacher", "admin"),
  Data.DeleteUser
);

module.exports = router;
