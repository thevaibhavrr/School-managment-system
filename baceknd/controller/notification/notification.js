const Notification = require("../../model/notification/notification");
const Notification2 = require("../../model/notification/notification2");
const Trycatch = require("../../middleware/TryCatch");
const User = require("../../model/User/User");

// Get a specific notification by ID

// // Create a new notification
// const createNotification = Trycatch(async (req, res, next) => {
//   req.body.createdByUser = req.user.id;
//   req.body.schoolId = req.user.schoolId;
//   const notification = await Notification.create(req.body);

//   const schoolId = req.user.schoolId;
//   if (notification.for) {
//     var role = notification.for;
//     var searchQuery = {
//       schoolId,
//       role, 
//     };
//   }
//   if (!notification.for) {
//     var searchQuery = {
//       schoolId,
//     };
//   }

//   const data = await User.find(searchQuery);
//   const toteluser = await data.length;
//   for (let i = 0; i < data.length; i++) {
//     const user = data[i];
//     var notificationsend = await Notification2.create({
//       notificationId: notification._id,
//       userId: user._id,
//     }); 
//   }
//   res.status(201).json({
//     message: "Notification send successfully",
//     send: `send notification to ${toteluser} , role is ${role}`,
//     notification,
//   });
// });


// Create a new notification
const createNotification = Trycatch(async (req, res, next) => {
  req.body.createdByUser = req.user.id;
  req.body.schoolId = req.user.schoolId;
  // notificaion created in table 1
  const notification = await Notification.create(req.body);
// create notification for 
  const schoolId = req.user.schoolId;
  if (notification.for) {
    var role = notification.for;
    var searchQuery = {
      schoolId,
      role,
    };
  }
  if (!notification.for) {
    var searchQuery = {
      schoolId,
    };
  }

  // Send notification to specific user by ID
  if (req.body.userId) {
    const user = await User.findOne({
      _id: req.body.userId,
      schoolId,
    });
    if (user) {
      const notificationsend = await Notification2.create({
        notificationId: notification._id,
        userId: user._id,
      });
      res.status(201).json({
        message: "Notification sent successfully to specific user",
        send: `Sent notification to user ID: ${user._id}`,
        notification,
      });
    } else {
      res.status(404).json({
        message: "User not found",
      });
    }
  }
  // Send notification to class ID
  else if (req.body.classId) {
    const users = await User.find({
      schoolId,
      classId: req.body.classId,
    });
    const totalUsers = users.length;
    for (let i = 0; i < users.length; i++) {
      const user = users[i];
      const notificationsend = await Notification2.create({
        notificationId: notification._id,
        userId: user._id,
      });
    }
    res.status(201).json({
      message: "Notification sent successfully to class",
      send: `Sent notification to class ID: ${req.body.classId}, Total users: ${totalUsers}`,
      notification,
    });
  }
  // Send notification to all users in the search query
  else {
    const data = await User.find(searchQuery);
    const totalUsers = data.length;
    for (let i = 0; i < data.length; i++) {
      const user = data[i];
      const notificationsend = await Notification2.create({
        notificationId: notification._id,
        userId: user._id,
      });
    }
    res.status(201).json({
      message: "Notification sent successfully",
      send: `Sent notification to ${totalUsers} users, role is ${role}`,
      notification,
    });
  }
});


// Get all notifications
const getAllNotifications = Trycatch(async (req, res) => {
  const schoolId = req.user.schoolId;
  var searchQuery = {
    schoolId,
  };
  const notifications = await Notification.find(searchQuery);
  const totalNotification = await notifications.length;
  res.json({ totalNotification, notifications });
});

// Get a specific notification by ID

const getNotificationById = Trycatch(async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  const notification = await Notification.findById(id);

  if (!notification) {
    return res.status(404).json({ message: "Notification not found" });
  }

  await Notification2.findOneAndUpdate(
    { notificationId: id, userId },
    { isview: true }
  );

  const updatedNotification2 = await Notification2.findOne({
    notificationId: id,
    userId,
  });

  const isview = updatedNotification2.isview;

  const updatedNotification = { ...notification.toObject(), isview };

  res.json({ notification: updatedNotification });
}); 

 
// Update a notification
const updateNotification = Trycatch(async (req, res) => {
  const { id } = req.params;
  const { title, description, status } = req.body;
  const notification = await Notification.findByIdAndUpdate(
    id,
    {
      title,
      description,
      status,
    
    },
    { new: true }
  );
  if (!notification) {
    return res.status(404).json({ message: "Notification not found" });
  }
  res.json(notification);
});

// Delete a notification
const deleteNotification = Trycatch(async (req, res, next) => {
  const { id } = req.params;
  const notification = await Notification.findByIdAndDelete(id);
  if (!notification) {
    return res.status(404).json({ message: "Notification not found" });
  }
  res.json({ message: "Notification deleted successfully" });
});


// mynotification
const mynotification = Trycatch(async (req, res, next) => {
  const userId = req.user.id;
  const searchQuery = {
    userId: userId,
  };

  const notificationIds = await Notification2.find(searchQuery)
    .distinct("notificationId")
    .exec();
  const notifications = await Notification.find({
    // _id: { $in: notificationIds }
    _id: notificationIds,
  });
  const totalNotification = await notifications.length;

  res.json({ totalNotification, notifications });
});

// delete notification
const deleteMyNotificationById = Trycatch(async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id;

  // Check if the notification exists
  const notification = await Notification.findById(id);
  if (!notification) {
    return res.status(404).json({ message: "Notification not found" });
  }


  // Delete the notification
  // await Notification.findByIdAndRemove(id);

  // Delete the corresponding Notification2 entry
  await Notification2.findOneAndRemove({ notificationId: id, userId });

  res.json({ notification, message: "Notification deleted successfully" });
});


module.exports = {
  createNotification,
  getAllNotifications,
  getNotificationById,
  updateNotification,
  deleteNotification,
  mynotification,
  deleteMyNotificationById
};
