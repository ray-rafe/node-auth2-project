const router = require("express").Router();
const bcrypt = require("bcryptjs");
const { add } = require("../users/users-model");
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const jwt = require("jsonwebtoken");
const { JWT_SECRET } = require("../secrets/index.js");

function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const options = {
    expiresIn: "1d",
  };
  return jwt.sign(payload, JWT_SECRET, options);
}

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const { username, password, role_name } = req.body;
    const hash = bcrypt.hashSync(password, 8);
    const user = { username, password: hash, role_name };
    const newUser = await add(user);
    res.status(201).json(newUser);
  } catch (error) {
    next(error);
  }
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  try {
    const { username, password } = req.user;
    if (bcrypt.compareSync(req.body.password, password)) {
      const token = buildToken(req.user);

      res.json({
        message: `${username} is back!`,
        token: token,
      });
    } else {
      next({ status: 401, message: "Invalid credentials" });
    }
  } catch (err) {
    next(err);
  }
});

module.exports = router;
