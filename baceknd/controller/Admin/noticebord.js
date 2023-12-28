const Notice = require("../../model/noticebord/noticebord");
const TryCatch = require("../../middleware/TryCatch");
const getDataUri = require("../../utils/dataUri")
const cloudinary = require("cloudinary")
// Create a new notice
const createNotice = TryCatch(async (req, res) => {
  const { title, content } = req.body;
  const schoolId = req.user.schoolId;
  const createdBy = req.user.id
  // file upload
  const file = req.file;
  const fileUri = getDataUri(file)
  // using cloudnary
  const mycloud = await cloudinary.v2.uploader.upload(fileUri.content)
  // createing notice
  const notice = await Notice.create({
    title,
    content,
    schoolId,
    createdBy,
    noticeboardimage: {
      public_id: mycloud.public_id,
      url: mycloud.secure_url,
    },
  });

  res.status(201).json({ message: "Notice created successfully", notice });
});

// Get all notices
const getAllNotices = TryCatch(async (req, res) => {
  const { schoolId } = req.user.schoolId;

  //   const notices = await Notice.find(schoolId).populate("likedBy")
  const notices = await Notice.find(schoolId).populate({
    path: "likedBy",
    select: ["name", "email"],
  });
const rever = notices.reverse()
  res.status(200).json({ notices: rever });
});
// Get a notice by ID
const getNoticeById = TryCatch(async (req, res) => {
  const notice = await Notice.findById(req.params.id).populate({
    path: "likedBy",
    select: ["name", "email"],
  });

  if (!notice) {
    return res.status(404).json({ message: "Notice not found" });
  }

  res.status(200).json({ notice });
});

// like notice
const LikeNotice = TryCatch(async (req, res, next) => {
  const noticeId = req.params.id;
  const userId = req.user.id;
  const notice = await Notice.findById(noticeId);

  if (!notice) {
    return res.status(404).json({ message: "Notice not found" });
  }
  if (notice.likedBy.includes(userId)) {
    return res
      .status(400)
      .json({ message: "You have already liked this notice" });
  }
  notice.likes += 1;
  notice.likedBy.push(userId);
  await notice.save();
  res.status(200).json({ message: "Notice liked successfully", notice });
});

// Update a notice
const updateNotice = TryCatch(async (req, res) => {
  const { title, content } = req.body;
  const Id = req.params.id;
  const notice = await Notice.findByIdAndUpdate(
    Id,
    { title, content },
    { new: true }
  );

  if (!notice) {
    return res.status(404).json({ message: "Notice not found" });
  }

  res.status(200).json({ message: "Notice updated successfully", notice });
});

// Delete a notice
const deleteNotice = TryCatch(async (req, res) => {
  const notice = await Notice.findByIdAndDelete(req.params.id);

  if (!notice) {
    return res.status(404).json({ message: "Notice not found" });
  }

  res.status(200).json({ message: "Notice deleted successfully" });
});
module.exports = {
  createNotice,
  getAllNotices,
  getNoticeById,
  updateNotice,
  deleteNotice,
  LikeNotice,
};
