import { Request, Response } from "express";
import { validate } from "jsonschema";
import {
    AuthFinishRequest,
    AuthInitRequest,
    AuthInitialValues,
    Curves,
    DeserializationError,
    OwlServer,
    RegistrationRequest,
    UserCredentials,
    ZKPVerificationFailure,
} from "owl-ts";
import { TempValues, User } from "./database.js";
import schemas from "./json_schemas.js";

const cfg = {
    curve: Curves.P256,
    serverId: "localhost",
};

const server = new OwlServer(cfg);

export async function register_init(req: Request, res: Response) {
    if (!validate(req.body, schemas.owl.register.init)) {
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

export async function auth_init(req: Request, res: Response) {
    if (!validate(req.body, schemas.owl.auth.init)) {
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
    await TempValues.upsert({
        username: username,
        values: initial.serialize(),
    });

    return res.json(response.serialize());
}

export async function auth_finish(req: Request, res: Response) {
    if (!validate(req.body, schemas.owl.auth.finish)) {
        return res.status(400).send("Incorrect request JSON format");
    }
    const { username, finish, kc } = req.body;

    // find initial values by username
    const initial = await TempValues.findByPk(username);
    if (!initial) {
        return res
            .status(400)
            .send("Initial auth values do not exist for this user");
    }

    // deserialize initial values
    const init = AuthInitialValues.deserialize(initial.values, cfg);
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
    const loginSuccess = await server.authFinish(username, finishReq, init);
    if (loginSuccess instanceof Error) {
        return res.status(400).send(loginSuccess.message);
    }

    // optional key confirmation check
    if (loginSuccess.kcTest != kc) {
        return res.status(400).send("Key confirmation failed");
    }

    // server-side login stuff would go here

    // send success
    return res.json({
        message: "Login successful",
        kc: loginSuccess.kc,
    });
}
