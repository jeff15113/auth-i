exports.up = function(knex, Promise) {
  return knex.schema
    .createTable("users", users => {
      users.increments("id");
      users.string("username");
      users.string("password");
      users.boolean("active");
    })
    .then(() => console.log("Created Users Table"));
};

exports.down = function(knex, Promise) {};
