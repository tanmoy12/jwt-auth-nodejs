const mongoose = require("mongoose");
const Schema = mongoose.Schema;

// User Schema
const UserSchema = new Schema({
  username: String,
  password: String
});

// Session Schema
const SessionSchema = new Schema({
  userId: Schema.Types.ObjectId,
  lastRefreshed: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model("users", UserSchema);
const Session = mongoose.model("sessions", SessionSchema);

module.exports.User = User;
module.exports.Session = Session;