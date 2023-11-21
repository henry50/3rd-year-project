import express, { Request, Response, NextFunction } from "express";
import path from "path";
import { fileURLToPath } from "url";
import session from "express-session";
import dotenv from "dotenv";
// make this swappable with ./owl_server.ts??
import {
    register_init,
    register_finish,
} from "./opaque_server.js";

dotenv.config();

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
app.use("/static", express.static(path.join(__dirname, "..", "static")));
app.use(express.urlencoded({ extended: false }));
app.use(session({
    resave: false, // don't save session if unmodified
    saveUninitialized: false, // don't create session until something stored
    secret: "dfa191237eb608ad50a500200e98bcb208735c2a4f7d78a1956c00ef851c5383"
}));

function restrict(req: Request, res: Response, next: NextFunction) {
    if (req.session.user) {
        next();
    } else {
        req.session.error = "Access denied!";
        res.redirect("/login");
    }
}

app.get("/", function(req, res){
    res.redirect("/login");
});

app.get("/restricted", function(req, res){
    res.send("Wahoo! restricted area, click to <a href=\"/logout\">logout</a>");
});

app.get("/logout", function(req, res){
    // destroy the user"s session to log them out
    // will be re-created next request
    req.session.destroy(function(){
        res.redirect("/");
    });
});

app.post("/register/register-init", register_init);

app.post("/register/register-finish", register_finish);

app.get("/register", function(req, res){
    res.render("register");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.post("/login", function (req, res, next) {
    res.send("not implemented :(");
});

const port = process.env.PORT;
app.listen(port);
console.log(`Express started on port ${port}`);
