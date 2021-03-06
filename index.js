const express = require("express");
//const helmet = require('helmet');
//const cors = require('cors');
const bcrypt = require("bcrypt");

const db = require("./dbConfig.js");
const Users = require("./userdb.js");

const server = express();

//server.use(helmet());
server.use(express.json());
//server.use(cors());

server.post("/api/register", (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10);

  user.password = hash;

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post("/api/login", (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Willkommen, ${user.username}!` });
      } else {
        res.status(401).json({ message: "Invalid Credentials" });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function restricted(req, res, next) {
  const { username, password } = req.headers;

  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(401).json({ message: "You shall not pass!" });
        }
      })
      .catch(error => {
        res.status(500).json({ message: "Ran into an unexpected error" });
      });
  } else {
    res.status(400).json({ message: "Thou lefed thyne fields null" });
  }
}

server.get("/api/users", restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

const port = process.env.PORT || 4000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
