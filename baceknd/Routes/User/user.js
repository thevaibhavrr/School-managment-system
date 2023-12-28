const express = require("express");
const router = express.Router();
const User = require("../../controller/UserController/User");
const auth = require("../../middleware/Auth");
const upload = require("../../middleware/multer")
const singeupload = require("../../middleware/multer2")
// Routes for super admin

// register a new user
// router.post("/register", upload.single("profilepic"), User.AddUser);
router.post("/register", User.AddUser);


// login 
router.post("/login", User.UserLogin);


// get a user by ID
router.get(
  "/userbyId/:id",
  auth.isAuthenticateUser,
  User.UserbyId
);
// get a user by classID
router.get(
  "/student-by-classId/:id",
  auth.isAuthenticateUser,
  User.StudentByClassID
);

//  update a user by ID
router.put(
  "/updateusers/:id",
  auth.isAuthenticateUser,
  singeupload,
  // auth.authorizeRole("superAdmin"),
  User.UpdateUser
);

// / update a user by ID
router.delete(
  "/deleteusers/:id",
  auth.isAuthenticateUser,
  // auth.authorizeRole("superAdmin"),
  User.DeleteUser
);


// get all users
router.get(
  "/Alluser",
  auth.isAuthenticateUser,
  auth.authorizeRole("superAdmin"),
  User.AllUser
);



// Route for user logout
router.post("/logout", auth.isAuthenticateUser, User.LogOut);

// get user details
router.get("/me", auth.isAuthenticateUser, User.UserDetails);


module.exports = router;
