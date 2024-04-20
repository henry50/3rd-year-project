import dotenv from "dotenv";
import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import {
    auth_finish,
    auth_init,
    register_finish,
    register_init,
} from "./owl_routes.js";
dotenv.config();

// __dirname workaround for esm
const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const app = express();

// config
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "..", "views"));

// middleware
app.use(express.json());
app.use("/dist", express.static(path.join(__dirname, "..", "dist")));
app.use(express.urlencoded({ extended: false }));

app.get("/", function (_, res) {
    res.redirect("/login");
});

app.post("/register/register-init", register_init);

app.post("/register/register-finish", register_finish);

app.get("/register", function (_, res) {
    res.render("register");
});

app.get("/login", function (_, res) {
    res.render("login");
});

app.post("/login/login-init", auth_init);

app.post("/login/login-finish", auth_finish);

const port = process.env.PORT;
app.listen(port);
console.log(`Express started on port ${port}`);
