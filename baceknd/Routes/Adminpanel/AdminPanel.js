const experss = require("express");
const router = experss.Router();
const Data = require("../../controller/Dashboard/Superadminpanel");
const auth = require("../../middleware/Auth");

router
  .route("/adminpanel")
  .get(
    auth.isAuthenticateUser,
    auth.authorizeRole("superAdmin"),
    Data.SuperAdminPanel
  );
router
  .route("/adminpanelforadmin")
  .get(auth.isAuthenticateUser, auth.authorizeRole("admin"), Data.AdminPanel);
router
  .route("/adminpanelforteacher")
  .get(
    auth.isAuthenticateUser,
    auth.authorizeRole("admin", "teacher"),
    Data.TeacherPanel
  );
router
  .route("/adminpanelforstudent")
  .get(
    auth.isAuthenticateUser,
    auth.authorizeRole("student"),
    Data.StudentPanel
  );

module.exports = router;
