const express = require("express");
const router = express.Router();
const data = require("../../controller/SchoolClass/classroutine");
const auth = require("../../middleware/Auth");

router
  .route("/add-class-routines")
  .post(auth.isAuthenticateUser, data.createClassRoutine);
router
  .route("/class-routines")
  .get(auth.isAuthenticateUser, data.getClassRoutinesBySchool);
router
  .route("/class-routines/:classId")
  .get(auth.isAuthenticateUser, data.getClassRoutinesBySclassId)
  router
    .route("/class-routines/:id")
    .put(auth.isAuthenticateUser, data.updateClassRoutine)
    .delete(auth.isAuthenticateUser, data.deleteClassRoutine);

    router.route("/my-class-routine").get(auth.isAuthenticateUser , data.MySchoolRoutine)
// router
//   .route("/my-notification")
//   .get(auth.isAuthenticateUser, Notification.mynotification);
// router
//   .route("/delete-my-notification/:id")
//   .delete(auth.isAuthenticateUser, Notification.deleteMyNotificationById);
module.exports = router;
