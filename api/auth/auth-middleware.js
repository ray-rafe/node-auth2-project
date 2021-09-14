const { JWT_SECRET } = require("../secrets/index");
const jwt = require("jsonwebtoken");
const { findBy } = require("../users/users-model");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        next({ status: 401, message: "Token invalid" });
      } else {
        req.decodedJwt = decoded;
        next();
      }
    });
  } else {
    next({ status: 401, message: "Token required" });
  }
};

const only = (role) => (req, res, next) => {
  if (req.decodedJwt.role_name === role) {
    next();
  } else {
    next({ status: 403, message: "This is not for you" });
  }
};

async function checkUsernameExists(req, res, next) {
  try {
    const { username } = req.body;
    const user = await findBy({ username: username });
    if (user.length) {
      req.user = user[0];
      next();
    } else {
      next({
        status: 401,
        message: "Invalid credentials",
      });
    }
  } catch (err) {
    next(err);
  }
}

const validateRoleName = (req, res, next) => {
  if (req.body.role_name) {
    req.body.role_name = req.body.role_name.trim();
  } else {
    req.body.role_name = "student";
  }
  const { role_name } = req.body;

  if (!role_name || role_name === "") {
    req.body.role_name = "student";
  } else if (role_name.length > 32) {
    next({ status: 422, message: "Role name can not be longer than 32 chars" });
  } else if (role_name === "admin") {
    next({ status: 422, message: "Role name can not be admin" });
  }
  next();
};

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
};
