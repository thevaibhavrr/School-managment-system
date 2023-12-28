const mongoose = require("mongoose");

// Create a notice schema
const noticeSchema = new mongoose.Schema({
  title: {
    type: String,
    required: true,
  },
  content: {
    type: String,
    required: true,
  },
  date: {
    type: Date,
    default: Date.now,
  },
  image: {
    type: String,
  },
  schoolId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Schools",
  },
  likes: {
    type: Number,
    default: 0,
  },
  createdBy: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "Users",
  },
  //   expiresAt: {
  //     type: Date,
  //     default: Date.now,
  //     expires: "24h",
  //   },
  // expireAt: {
  //   type: Date,
  //   default: Date.now,
  //   expires: 10000,
  // },
  // expireAt: {
  //   type: Date,
  //   required: true,
  //   default: Date.now,
  // },
  noticeboardimage: {
    public_id: {
      type: String,
    },
    url: {
      type: String,
    },
  },
  likedBy: [
    {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Users",
    },
  ],
});

// noticeSchema.index({ expireAt: 1 }, { expireAfterSeconds: 2 });

// Create a notice model
module.exports = mongoose.model("Notice", noticeSchema);
