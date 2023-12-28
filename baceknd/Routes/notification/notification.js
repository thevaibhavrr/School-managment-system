const express = require("express");
const router = express.Router();
const auth = require("../../middleware/Auth");
const Notification = require("../../controller/notification/notification");

router
  .route("/send_notification")
  .post(auth.isAuthenticateUser, Notification.createNotification);
router
  .route("/all_notification")
  .get(auth.isAuthenticateUser, Notification.getAllNotifications);
router
  .route("/notification/:id")
  .get(auth.isAuthenticateUser, Notification.getNotificationById)
  .put(auth.isAuthenticateUser, Notification.updateNotification)
  .delete(auth.isAuthenticateUser, Notification.deleteNotification);
router
  .route("/my-notification")
  .get(auth.isAuthenticateUser, Notification.mynotification);
  router
    .route("/delete-my-notification/:id")
    .delete(auth.isAuthenticateUser, Notification.deleteMyNotificationById);
module.exports = router;
