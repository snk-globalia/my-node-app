const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../models/User");

const router = express.Router();
const JWT_SECRET = "YOUR_SECRET_KEY";

router.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name && !email && !password) {
      return res.status(400).json({ message: "all fields are required" });
    }

    if (!name && !email) {
      return res
        .status(400)
        .json({ message: "name and email fields are required" });
    }
    if (!email && !password) {
      return res
        .status(400)
        .json({ message: "email and password fields are required" });
    }
    if (!name && !password) {
      return res
        .status(400)
        .json({ message: "name and password fields are required" });
    }

    if (!name) {
      return res.status(400).json({ message: "name field is required" });
    }
    if (!email) {
      return res.status(400).json({ message: "email field is required" });
    }
    if (!password) {
      return res.status(400).json({ message: "password field is required" });
    }

    let user = await User.findOne({ email });
    if (user) {
      return res.status(400).json({ message: "user already exists" });
    }

    const hashedPass = await bcrypt.hash(password, 10);

    user = new User({ name, email, password: hashedPass });
    await user.save();

    res.json({ message: "user registered successfully" });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "server error" });
  }
});

router.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email && !password) {
      return res
        .status(400)
        .json({ message: "email and password are required" });
    }

    if (!email) {
      return res.status(400).json({ message: "email field is required" });
    }

    if (!password) {
      return res.status(400).json({ message: "password field is required" });
    }

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "user does not exist" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: "incorrect password" });
    }

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "1d" });

    res.json({
      message: "login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ message: "server error" });
  }
});

router.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ message: "email field is required" });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ message: "user not found" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    user.otp = otp;
    user.otpExpire = Date.now() + 5 * 60 * 1000;

    await user.save();

    res.json({ message: "otp sent to email", otp });
  } catch (err) {
    console.log("forgot Password Error:", err);
    res.status(500).json({ message: "server error" });
  }
});

router.post("/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ message: "all fields are required" });
    }

    if (!email && !otp) {
      return res
        .status(400)
        .json({ message: "email and otp fields are required" });
    }
    if (!otp && !newPassword) {
      return res
        .status(400)
        .json({ message: "otp and new password fields are required" });
    }
    if (!email && !newPassword) {
      return res
        .status(400)
        .json({ message: "email and new password fields are required" });
    }

    const user = await User.findOne({
      email,
      otp,
      otpExpire: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({ message: "invalid or expired otp" });
    }

    const hashedPass = await bcrypt.hash(newPassword, 10);

    user.password = hashedPass;
    user.otp = undefined;
    user.otpExpire = undefined;

    await user.save();

    res.json({ message: "password reset successful" });
  } catch (err) {
    console.log("reset Password Error:", err);
    res.status(500).json({ message: "server error" });
  }
});

module.exports = router;
