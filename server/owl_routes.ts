import { Request, Response } from "express";
import { validate } from "jsonschema";
import { Expected, User } from "./database.js";
import BigNumber from "bignumber.js";
import OwlServer from "./owl_server.js";

const cfg = {
    p: "0xfd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7",
    q: "0x9760508f15230bccb292b982a2eb840bf0581cf5",
    g: "0xf7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a",
    serverId: "localhost"
}

const server = new OwlServer(cfg);

const register_init_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string"},
        "T": {"type": "string"},
        "pi": {"type": "string"}
    }
};

export async function register_init(req: Request, res: Response){
    if(!validate(req.body, register_init_schema)){
        return res.status(400).send("Incorrect JSON format");
    }
    const {username, T, pi} = req.body;
    // check if user already exists
    const existing = await User
        .findByPk(username)
        .then(result => result !== null);
    if(existing){
        return res.status(400).send("Username taken");
    }
    // create user record
    const {X3, PI3} = await server.register();
    const user_serialised = {
        X3: X3.toString(16),
        PI3: {
            h: PI3.h.toString(16),
            r: PI3.r.toString(16)
        },
        pi: pi,
        T: T
    }
    // save user record to database
    await User.create({
        username: username,
        credentials: user_serialised
    });
    return res.json({
        username: username,
        message: "'" + username + "' registered successfully"
    });
}

export async function register_finish(req: Request, res: Response){
    // owl does not have a second registration flow, this is included
    // for compatibility with OPAQUE
    return res.status(404);
}

const auth_init_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string"},
        "X1": {"type": "string"},
        "X2": {"type": "string"},
        "PI1": {
            "type": "object",
            "properties": {
                "h": {"type": "string"},
                "r": {"type": "string"}
            }
        },
        "PI2": {
            "type": "object",
            "properties": {
                "h": {"type": "string"},
                "r": {"type": "string"}
            }
        }
    }
}

export async function auth_init(req: Request, res: Response){
    if(!validate(req.body, auth_init_schema)){
        return res.status(400).send("Incorrect JSON format");
    }
    const {username, X1, X2, PI1, PI2} = req.body;
    // check if user exists
    const user = await User.findByPk(username);
    if(!user){
        return res.status(404).send("User not found in database");
    }
    const {X3, PI3, pi, T} = user.credentials;
    // get initial auth values
    const {X4, PI4, beta, PIBeta} = await server.authInit(username, BigNumber(pi), BigNumber(T), BigNumber(X1), BigNumber(X2), BigNumber(X3),
                            {h: BigNumber(PI1.h), r: BigNumber(PI1.r)}, {h: BigNumber(PI2.h), r: BigNumber(PI2.r)},
                                {h: BigNumber(PI3.h), r: BigNumber(PI3.r)});
    return res.json({
        X4: X4.toString(16),
        PI4: {
            h: PI4.h.toString(16),
            r: PI4.r.toString(16)
        },
        beta: beta.toString(16),
        PIBeta: {
            h: PIBeta.h.toString(16),
            r: PIBeta.r.toString(16)
        }
    });
}

const auth_finish_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string"},
        "alpha": {"type": "string"},
        "PIAlpha": {
            "type": "object",
            "properties": {
                "h": {"type": "string"},
                "r": {"type": "string"}
            }
        },
        "r": {"type": "string"}
    }
}

export async function auth_finish(req: Request, res: Response){
    if(!validate(req.body, auth_finish_schema)){
        return res.status(400).send("Incorrect JSON format");
    }
    const {username, alpha, PIAlpha, r} = req.body;
    const login_success = await server.authFinish(BigNumber(alpha), {h: BigNumber(PIAlpha.h), r: BigNumber(PIAlpha.r)}, BigNumber(r));
    if(login_success){
        // do actual login stuff
        return res.send("<p>Login successful</p>");
    } else{
        return res.send("<p>Login failure :(</p>");
    }

}