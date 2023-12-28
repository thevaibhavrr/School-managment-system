const express = require("express");
const router = express.Router();
const data = require("../../controller/SchoolClass/classection");
const auth = require("../../middleware/Auth");

router
  .route("/sections")
  .post(
    auth.isAuthenticateUser,
    auth.authorizeRole("admin", "teacher"),
    data.createSection
  )
  .get(
    auth.isAuthenticateUser,
    auth.authorizeRole("admin", "teacher"),
    data.getSections
  );

router
  .route("/sections/:id")
  .get(
    auth.isAuthenticateUser,
    auth.authorizeRole("admin", "teacher"),
    data.getSectionById
  )
  .put(
    auth.isAuthenticateUser,
    auth.authorizeRole("admin", "teacher"),
    data.updateSection
  )
  .delete(
    auth.isAuthenticateUser,
    auth.authorizeRole("admin", "teacher"),
    data.deleteSection
  );
  router.get(
    "/sections/byclass/:id",
    auth.isAuthenticateUser,
    auth.authorizeRole("admin", "teacher"),
    data.getSectionsByClassId
  );

module.exports = router;
