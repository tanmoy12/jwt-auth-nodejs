const express = require("express");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const { User, Session } = require("./models");
require("dotenv").config();

mongoose.connect(process.env.DB_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

const app = express();

const bodyParser = require("body-parser");

app.use(bodyParser.urlencoded({ extended: true })); // limit: '200mb',
app.use(bodyParser.json());

authenticate = async (req, res, next) => {
  try {
    const accessToken = req.headers["authorization"];
    const { username, tokenId, userId } = jwt.verify(accessToken, process.env.SECRET);
    req.user = { username, tokenId, userId };

    const session = await Session.findOne({ _id: tokenId });
    console.log(session);
    if (!session) return res.sendStatus(401);

    next();
  } catch (err) {
    console.log(err);
    return res.sendStatus(401);
  }
}

app.use("/signup", async (req, res) => {
  const newUser = new User({
    username: req.body.username,
    password: req.body.password
  });
  await newUser.save();
  return res.sendStatus(200);
})

app.use("/login", async (req, res) => {
  const user = await User.findOne({
    username: req.body.username,
    password: req.body.password
  })
  if (!user) return res.sendStatus(400);

  let newSession = new Session({ userId: user._id });
  newSession = await newSession.save();

  const payload = { tokenId: newSession._id, userId: user._id, username: user.username };

  const accessToken = jwt.sign(payload, process.env.SECRET, { expiresIn: `${process.env.EXPIRE_ACCESS_MINUTES}m` });
  const refreshToken = jwt.sign(payload, process.env.SECRET, { expiresIn: `${process.env.EXPIRE_REFRESH_MINUTES}m` });

  return res.json({ accessToken, refreshToken });
})

app.use("/refresh/:token", async (req, res) => {
  try {
    const refreshTokenReq = req.params.token;
    const { username, tokenId, userId } = jwt.verify(refreshTokenReq, process.env.SECRET);

    const session = await Session.findOneAndUpdate(
      { _id: tokenId },
      {
        $set: { lastRefreshed: new Date() }
      },
      { new: true }
    );
    if (!session) return res.sendStatus(400);

    const payload = { tokenId, userId, username };

    const accessToken = jwt.sign(payload, process.env.SECRET, { expiresIn: `${process.env.EXPIRE_ACCESS_MINUTES}m` });
    const refreshToken = jwt.sign(payload, process.env.SECRET, { expiresIn: `${process.env.EXPIRE_REFRESH_MINUTES}m` });

    return res.json({ accessToken, refreshToken });
  } catch (err) {
    return res.sendStatus(400);
  }
})

app.use("/logout", authenticate, async (req, res) => {
  await Session.deleteOne({ _id: req.user.tokenId });
  res.sendStatus(200);
})

app.use("/logoutall", authenticate, async (req, res) => {
  await Session.deleteMany({ userId: req.user.userId });
  res.sendStatus(200);
})

app.use("/private", authenticate, (req, res) => {
  return res.sendStatus(200);
})

const cron = require("node-cron");

cron.schedule("0 0 * * *", async () => {
  await Session.deleteMany({
    lastRefreshed: {
      $lt: new Date((new Date()).getTime() - 1000 * 60 * parseInt(process.env.EXPIRE_REFRESH_MINUTES))
    }
  })
});

const PORT = 9000;
app.listen(PORT, () => console.log(`Running on ${PORT}`));