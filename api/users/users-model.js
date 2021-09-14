const db = require("../../data/db-config.js");

function find() {
  return db("users as u")
    .join("roles as r", "r.role_id", "u.role_id")
    .select("u.user_id", "u.username", "r.role_name");
}

function findBy(filter) {
  return db("users as u")
    .join("roles as r", "r.role_id", "u.role_id")
    .where(filter)
    .select("u.user_id", "u.username", "u.password", "r.role_name");
}

function findById(user_id) {
  return db("users as u")
    .join("roles as r", "r.role_id", "u.role_id")
    .where("u.user_id", user_id)
    .select("u.user_id", "u.username", "r.role_name")
    .first();
}

async function add({ username, password, role_name }) {
  let created_user_id;
  await db.transaction(async (trx) => {
    let role_id_to_use;
    const [role] = await trx("roles").where("role_name", role_name);
    if (role) {
      role_id_to_use = role.role_id;
    } else {
      const [role_id] = await trx("roles").insert({
        role_name: role_name.trim(),
      });
      role_id_to_use = role_id;
    }
    const [user_id] = await trx("users").insert({
      username,
      password,
      role_id: role_id_to_use,
    });
    created_user_id = user_id;
  });
  return findById(created_user_id);
}

module.exports = {
  add,
  find,
  findBy,
  findById,
};
