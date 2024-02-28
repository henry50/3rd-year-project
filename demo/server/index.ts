import express, { Request, Response, NextFunction } from "express";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import dotenv from "dotenv";
dotenv.config();
import {
    register_init,
    register_finish,
    auth_init,
    auth_finish,
} from "./owl_routes.js";

// __dirname workaround for esm
const __dirname = path.dirname(fileURLToPath(import.meta.url));

export var app = express();

declare module "express-session" {
    interface SessionData {
        user: string;
        error: string;
    }
}

// config
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "..", "views"));

// middleware
app.use(express.json());
app.use("/dist", express.static(path.join(__dirname, "..", "dist")));
app.use(express.urlencoded({ extended: false }));
app.use(
    session({
        resave: false, // don't save session if unmodified
        saveUninitialized: false, // don't create session until something stored
        secret: "dfa191237eb608ad50a500200e98bcb208735c2a4f7d78a1956c00ef851c5383",
    }),
);

function restrict(req: Request, res: Response, next: NextFunction) {
    if (req.session.user) {
        next();
    } else {
        req.session.error = "Access denied!";
        res.redirect("/login");
    }
}

app.get("/", function (req, res) {
    res.redirect("/login");
});

app.post("/register/register-init", register_init);

app.post("/register/register-finish", register_finish);

app.get("/register", function (req, res) {
    res.render("register");
});

app.get("/login", function (req, res) {
    res.render("login");
});

app.post("/login/login-init", auth_init);

app.post("/login/login-finish", auth_finish);

app.get("/restricted", function (req, res) {
    res.send(
        `You are logged in as ${req.session.user}.  <a href="/logout">Log out</a>`,
    );
});

app.get("/logout", function (req, res) {
    // destroy the user"s session to log them out
    // will be re-created next request
    req.session.destroy(function () {
        res.redirect("/");
    });
});

const port = process.env.PORT;
app.listen(port);
console.log(`Express started on port ${port}`);
