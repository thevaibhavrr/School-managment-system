const mongoose = require("mongoose");
mongoose.set("strictQuery", false);

const connectDb = async () => {
  try {
    await mongoose.connect(process.env.DB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("Connected to MongoDB Database");
  } catch (error) {
    console.error("Unable to connect to MongoDB Database:", error);
  }
};

module.exports = connectDb;
