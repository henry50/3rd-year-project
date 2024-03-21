import { Request, Response } from "express";
import { validate } from "jsonschema";
import { Expected, User } from "./database.js";
import {
    OwlServer,
    AuthFinishRequest,
    AuthInitRequest,
    RegistrationRequest,
    UserCredentials,
    AuthInitialValues,
    DeserializationError,
    Curves,
    ZKPVerificationFailure,
} from "owl-ts";

const cfg = {
    curve: Curves.P256,
    serverId: "localhost",
};

const server = new OwlServer(cfg);

const register_init_schema = {
    type: "object",
    properties: {
        username: { type: "string" },
        data: {
            type: "object",
            properties: {
                T: { type: "string" },
                pi: { type: "string" },
            },
        },
    },
};

export async function register_init(req: Request, res: Response) {
    if (!validate(req.body, register_init_schema)) {
        return res.status(400).send("Incorrect request JSON format");
    }
    const { username, data } = req.body;
    // check if user already exists
    const existing = await User.findByPk(username).then(
        (result) => result !== null,
    );
    if (existing) {
        return res
            .status(400)
            .send("That username is already in use, please choose another");
    }
    // create user record
    const regRequest = RegistrationRequest.deserialize(data, cfg);
    if (regRequest instanceof DeserializationError) {
        return res.status(400).send("Invalid request data");
    }
    const credentials = await server.register(regRequest);
    // save user record to database
    await User.create({
        username: username,
        credentials: credentials.serialize(),
    });
    return res.send("Registration successful!");
}

export async function register_finish(req: Request, res: Response) {
    // owl does not have a second registration flow, this is included
    // for compatibility with OPAQUE
    return res.sendStatus(404);
}

const auth_init_schema = {
    type: "object",
    properties: {
        username: { type: "string" },
        init: {
            type: "object",
            properties: {
                X1: { type: "string" },
                X2: { type: "string" },
                PI1: {
                    type: "object",
                    properties: {
                        h: { type: "string" },
                        r: { type: "string" },
                    },
                },
                PI2: {
                    type: "object",
                    properties: {
                        h: { type: "string" },
                        r: { type: "string" },
                    },
                },
            },
        },
    },
};

export async function auth_init(req: Request, res: Response) {
    if (!validate(req.body, auth_init_schema)) {
        return res.status(400).send("Incorrect request JSON format");
    }
    const { username, init } = req.body;

    // check if user exists
    const user = await User.findByPk(username);
    if (!user) {
        return res.status(400).send("Incorrect username or password");
    }

    // deserialize stored credentials
    const credentials = UserCredentials.deserialize(user.credentials, cfg);
    if (credentials instanceof DeserializationError) {
        return res
            .status(500)
            .send("Internal error: Could not deserialize user credentials");
    }

    // deserialize request
    const authRequest = AuthInitRequest.deserialize(init, cfg);
    if (authRequest instanceof DeserializationError) {
        return res.status(400).send("Invalid request data");
    }

    // get initial auth values
    const authInit = await server.authInit(username, authRequest, credentials);
    if (authInit instanceof ZKPVerificationFailure) {
        return res.status(400).send(authInit.message);
    }
    const { initial, response } = authInit;

    // store initial values for authFinish
    await Expected.upsert({
        username: username,
        expected: initial.serialize(),
    });

    return res.json(response.serialize());
}

const auth_finish_schema = {
    type: "object",
    properties: {
        username: { type: "string" },
        finish: {
            type: "object",
            properties: {
                alpha: { type: "string" },
                PIAlpha: {
                    type: "object",
                    properties: {
                        h: { type: "string" },
                        r: { type: "string" },
                    },
                },
                r: { type: "string" },
            },
        },
        kc: { type: "string" },
    },
};

export async function auth_finish(req: Request, res: Response) {
    if (!validate(req.body, auth_finish_schema)) {
        return res.status(400).send("Incorrect request JSON format");
    }
    const { username, finish, kc } = req.body;

    // find initial values by username
    const initial = await Expected.findByPk(username);
    if (!initial) {
        return res
            .status(400)
            .send("Initial auth values do not exist for this user");
    }

    // deserialize initial values
    const init = AuthInitialValues.deserialize(initial.expected, cfg);
    // delete initial values
    await initial.destroy();
    if (init instanceof DeserializationError) {
        return res
            .status(500)
            .send("Internal error: Could not deserialize initial auth values");
    }

    // deserialize request
    const finishReq = AuthFinishRequest.deserialize(finish, cfg);
    if (finishReq instanceof DeserializationError) {
        return res.status(400).send("Invalid request data");
    }

    // finish auth, determine is user is authenticated
    const login_success = await server.authFinish(username, finishReq, init);
    if (login_success instanceof Error) {
        return res.status(400).send(login_success.message);
    }

    // optional key confirmation check
    if (login_success.kcTest != kc) {
        return res.status(400).send("Key confirmation failed");
    }

    // server-side login stuff would go here

    // send success
    return res.json({
        message: "Login successful",
        kc: login_success.kc,
    });
}
