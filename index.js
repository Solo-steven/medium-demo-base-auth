const express = require("express");
const app = express();
const port = 3010;
const path = require("path");
const crypto = require("crypto");
const mockDatabase = [];

app.use(express.urlencoded());
app.use(express.json());
app.use(express.static("pages"));

function generateHashPassword(password) {
  const salt = crypto.randomBytes(32).toString("hex");
  const hash = crypto
    .pbkdf2Sync(password, salt, 1000, 64, "sha512")
    .toString("hex");
  return { hash, salt };
}
app.post("/api/register", (req, res) => {
  const { email, password } = req.body;
  const { hash, salt } = generateHashPassword(password);
  mockDatabase.push({ email, hash, salt });
  console.log(
    `New User Register.\n email is ${email}.\n hash is ${hash}.\n salt is ${salt}`
  );
  res.redirect("/login.html");
});

function verifyPassword(password, hash, salt) {
  return (
    hash ===
    crypto.pbkdf2Sync(password, salt, 1000, 64, "sha512").toString("hex")
  );
}

app.post("/api/login", (req, res) => {
  const { email, password } = req.body;
  const user = mockDatabase.filter((user) => user.email === email)[0];
  if (verifyPassword(password, user.hash, user.salt)) {
    const idvalue = String(Math.random());
    user.id = idvalue;
    return res.cookie("id", idvalue).redirect("/protected");
  }
  return res.json({ messsage: "error unAuth user" });
});

app.get("/protected", (req, res) => {
  const cookies = req.get("cookie");
  const id = cookies.split("; ").filter(cookieString => cookieString.split("=")[0] === "id")[0].split("=")[1];
  for(const user of mockDatabase) {
      if(user.id === id) {
        return res.sendFile(path.resolve(__dirname, "protected", "protect.html"));
      }
  }
  res.sendFile(path.resolve(__dirname, "protected", "error.html"));
});

app.get("/", (req, res) => {
  res.redirect("/register.html");
});

app.listen(port, () => {
  console.log(`Example app listening at http://localhost:${port}`);
});
