const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const bodyParser = require("body-parser");
const Error = require("./middleware/error");

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

// Routes
const NotificationRoutes = require("./Routes/notification/notification");
const SchoolClassRoutes = require("./Routes/schoolClass/schoolclass");
const ClassRoutineRoutes = require("./Routes/schoolClass/classroutine");
const FeesRoutes = require("./Routes/Admin/Fees");
const AdminPanelRoutes = require("./Routes/Adminpanel/AdminPanel");
const SchoolRoutes = require("./Routes/SuperAdmin/Schoolroute");
const AddAdminRoutes = require("./Routes/SuperAdmin/Adminroute");
const AddTeacherRoutes = require("./Routes/Admin/AddTeacher");
const ExamRoutes = require("./Routes/ExamRoutes/Exam");
const NoticeboardRoutes = require("./Routes/Admin/noticebord");
const AddStudentRoutes = require("./Routes/Teacher/AddStudent");
const UserRoutes = require("./Routes/User/user");
const SectionRoutes = require("./Routes/schoolClass/classection");

app.use("/", NotificationRoutes);
app.use("/", ClassRoutineRoutes);
app.use("/", FeesRoutes);
app.use("/", AdminPanelRoutes);
app.use("/", SchoolRoutes);
app.use("/", AddAdminRoutes);
app.use("/", AddTeacherRoutes);
app.use("/", ExamRoutes);
app.use("/", NoticeboardRoutes);
app.use("/", AddStudentRoutes);
app.use("/", UserRoutes);
app.use("/", SectionRoutes);
app.use("/", SchoolClassRoutes);

// middelwear for error
app.use(Error);

module.exports = app;
