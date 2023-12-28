const express = require("express");
const router = express.Router();
const auth = require("../../middleware/Auth");
const Schooldata = require("../../controller/SuperAdmin/School");
const singeupload= require("../../middleware/multer2")
// Routes for managing schools

// create a new school
router.post(
  "/createschool",
  auth.isAuthenticateUser,
  auth.authorizeRole("superAdmin"),
  singeupload,
  Schooldata.AddSchool
);

// get all schools
router.get(
  "/allschool",
  auth.isAuthenticateUser,
  auth.authorizeRole("superAdmin"),
  Schooldata.AllSchool
);
// get all schools
router.get(
  "/myschool",
  auth.isAuthenticateUser,
  Schooldata.MySchoolDetails
);

// get school details by ID
router.get(
  "/schooldetails/:schoolId",
  auth.isAuthenticateUser,
  auth.authorizeRole("superAdmin", "admin"),
  Schooldata.SchoolDetails
);

// update school details by ID
router.put(
  "/updateschooldetails/:schoolId",
  auth.isAuthenticateUser,
  auth.authorizeRole("superAdmin","admin"),
  Schooldata.UpdateSchoolDetails
);

// delete a school by ID
router.delete(
  "/deleteschool/:schoolId",
  auth.isAuthenticateUser,
  auth.authorizeRole("superAdmin"),
  Schooldata.DeleteSchool
);

module.exports = router;
