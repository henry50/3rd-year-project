import { Request, Response } from "express";
import { validate } from "jsonschema";
import { Expected, User } from "./database.js";
import { OwlServer, AuthFinishRequest, AuthInitRequest, RegistrationRequest, UserCredentials, AuthInitialValues, DeserializationError } from "owl-ts";

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
        "data": {
            "type": "object",
            "properties": {
                "T": {"type": "string"},
                "pi": {"type": "string"}
            }
        }
    }
};

export async function register_init(req: Request, res: Response){
    if(!validate(req.body, register_init_schema)){
        return res.status(400).send("Incorrect JSON format");
    }
    const {username, data} = req.body;
    // check if user already exists
    const existing = await User
        .findByPk(username)
        .then(result => result !== null);
    if(existing){
        return res.status(400).send("Username taken");
    }
    // create user record
    const regRequest = RegistrationRequest.deserialize(data);
    if(regRequest instanceof DeserializationError){
        return res.status(400).send("Invalid request data");
    }
    const credentials = await server.register(regRequest);
    // save user record to database
    await User.create({
        username: username,
        credentials: credentials.serialize()
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
        "init": {
            "type": "object",
            "properties": {
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
    }
}

export async function auth_init(req: Request, res: Response){
    if(!validate(req.body, auth_init_schema)){
        return res.status(400).send("Incorrect JSON format");
    }
    const {username, init} = req.body;

    // check if user exists
    const user = await User.findByPk(username);
    if(!user){
        return res.status(404).send("User not found in database");
    }

    // deserialize stored credentials
    const credentials = UserCredentials.deserialize(user.credentials);
    if(credentials instanceof DeserializationError){
        return res.status(500).send("Could not deserialize user credentials");
    }

    // deserialize request
    const authRequest = AuthInitRequest.deserialize(init);
    if(authRequest instanceof DeserializationError){
        return res.status(400).send("Invalid request data");
    }
    
    // get initial auth values
    const authInit = await server.authInit(username, authRequest, credentials);
    if(authInit instanceof Error){
        return res.status(400).send(authInit.message);
    }
    const {initial, response} = authInit;

    // store initial values for authFinish
    await Expected.upsert({
        username: username,
        expected: initial.serialize()
    });

    return res.json(response.serialize());
}

const auth_finish_schema = {
    "type": "object",
    "properties": {
        "username": {"type": "string"},
        "finish": {
            "type": "object",
            "properties": {
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
    }
}

export async function auth_finish(req: Request, res: Response){
    if(!validate(req.body, auth_finish_schema)){
        return res.status(400).send("Incorrect JSON format");
    }
    const {username, finish} = req.body;

    // find initial values by username
    const initial = await Expected.findByPk(username);
    if(!initial){
        return res.status(404).send("Could not find initial auth values");
    }

    // deserialize initial values
    const init = AuthInitialValues.deserialize(initial.expected);
    if(init instanceof DeserializationError){
        return res.status(500).send("Could not deserialize initial auth values");
    }

    // deserialize request
    const finishReq = AuthFinishRequest.deserialize(finish);
    if(finishReq instanceof DeserializationError){
        return res.status(400).send("Invalid request data");
    }

    // finish auth, determine is user is authenticated
    const login_success = await server.authFinish(username, finishReq, init);

    if(login_success){
        // do session stuff
        return res.status(200).send();
    } else{
        return res.status(400).send("Incorrect username or password");
    }

}