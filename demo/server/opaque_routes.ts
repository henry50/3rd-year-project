import {
    getOpaqueConfig,
    OpaqueID,
    RegistrationRecord,
    CredentialFile,
    RegistrationRequest,
    OpaqueServer,
    KE1,
    KE3,
    ExpectedAuthResult
} from "@cloudflare/opaque-ts"
import { Request, Response } from "express";
import { validate } from "jsonschema";
import { Expected, User } from "./database.js";

const cfg = getOpaqueConfig(OpaqueID.OPAQUE_P256);

function fromHex(x: string): number[] {
    return Array.from(Buffer.from(x, 'hex'))
}

function getEnv(v: string): any{
    if(!process.env[v]){
        throw new Error(`Required environment variable '${v}' not set`);
    }
    return process.env[v];
}

const oprf_seed = fromHex(getEnv("OPRF_SEED"));
const server_ake_keypair = {
    "public_key": fromHex(getEnv("SERVER_AKE_PUBLIC_KEY")),
    "private_key": fromHex(getEnv("SERVER_AKE_PRIVATE_KEY"))
};
const server_identity = "localhost";

export const register_init_schema = {
    "type": "object",
    "properties": {
        "init": {
            "type": "array",
            "items": {"type": "integer"}
        },
        "username": {"type": "string"}
    }
};

export async function register_init(req: Request, res: Response) {
    if(!validate(req.body, register_init_schema)){
        return res.status(400).send("Incorrect JSON format");
    }
    const initSerialised = req.body.init;
    const credential_identifier = req.body.username.trim();
    // check if username is available
    const existing = await User
        .findByPk(credential_identifier)
        .then(result => result !== null);
    if(existing){
        return res.status(400).send("Username taken");
    }
    // create and run registration request
    const registrationRequest = RegistrationRequest.deserialize(cfg, initSerialised);
    const registrationServer = new OpaqueServer(cfg, oprf_seed, server_ake_keypair, server_identity);
    const registrationResponse = await registrationServer.registerInit(registrationRequest, credential_identifier);
    if (registrationResponse instanceof Error) {
        return res.status(500).send(`server failed to registerInit: ${registrationRequest}`);
    }
    return res.json({
        message: "username available, registration envelope enclosed",
        envelope: registrationResponse.serialize()
    });
}

const register_finish_schema = {
    "type": "object",
    "properties": {
        "record": {
            "type": "array",
            "items": {"type": "integer"}
        },
        "username": {"type": "string"}
    }
};

export async function register_finish(req: Request, res: Response) {
    if(!validate(req.body, register_finish_schema)){
        return res.status(400).send("Incorrect JSON format");
    }
    const recordSerialised = req.body.record;
    const credential_identifier = req.body.username.trim();
    const record = RegistrationRecord.deserialize(cfg, recordSerialised);
    const credential_file = new CredentialFile(credential_identifier, record, credential_identifier);
    // store credentials in database
    await User.create({
        username: credential_identifier,
        credentials: credential_file.serialize()
    });

    return res.json({
        username: credential_identifier,
        message: "'" + credential_identifier + "' registered"
    });
}

const auth_init_schema = {
    "type": "object",
    "properties": {
        "ke1": {
            "type": "array",
            "items": {"type": "integer"}
        },
        "username": {"type": "string"}
    }
};

export async function auth_init(req: Request, res: Response){
    if(!validate(req.body, auth_init_schema)){
        return res.status(400).send("Incorrect JSON format");
    }
    const ke1Serialised = req.body.ke1;
    const credential_identifier = req.body.username.trim();
    // look for user record
    const user = await User.findByPk(credential_identifier);
    if(!user){
        return res.status(404).send("User not found in database");
    }
    const credential_file = CredentialFile.deserialize(cfg, user.credentials);
    if(credential_file.credential_identifier != credential_identifier){
        return res.status(400).send("Credential identified does not match stored record");
    }
    const authServer = new OpaqueServer(cfg, oprf_seed, server_ake_keypair, server_identity);
    const ke1 = KE1.deserialize(cfg, ke1Serialised);
    const initiated = await authServer.authInit(
        ke1,
        credential_file.record,
        credential_file.credential_identifier,
        credential_file.credential_identifier 
    );
    if(initiated instanceof Error){
        return res.status(400).send(initiated.message);
    }
    const {ke2, expected} = initiated;
    // todo: check if record already exists
    await Expected.create({
        username: credential_identifier,
        expected: expected.serialize()
    });
    return res.json({
        message: "intermediate authentication key enclosed",
        ke2: ke2.serialize()
    });
}

const auth_finish_schema = {
    "type": "object",
    "properties": {
        "ke3": {
            "type": "array",
            "items": {"type": "integer"}
        },
        "username": {"type": "string"},
        "session_key": {
            "type": "array",
            "items": {"type": "integer"}
        }
    }
};

export async function auth_finish(req: Request, res: Response){
    if(!validate(req.body, auth_finish_schema)){
        return res.status(400).send("Incorrect JSON format");
    }
    const ke3Serialised = req.body.ke3;
    const credential_identifier = req.body.username;
    const client_session_key = req.body.session_key;
    const authServer = new OpaqueServer(cfg, oprf_seed, server_ake_keypair, server_identity);
    const ke3 = KE3.deserialize(cfg, ke3Serialised);
    const expected = await Expected.findByPk(credential_identifier);
    if(!expected){
        return res.status(404).send("Could not find expected auth result");
    }
    const expected_auth = ExpectedAuthResult.deserialize(cfg, expected.expected);
    const authFinish = authServer.authFinish(ke3, expected_auth);
    if(authFinish instanceof Error){
        return res.status(400).send(authFinish.message);
    }
    await expected.destroy();
    const {session_key: server_session_key} = authFinish;
    return res.json({
        message: "login success",
        client_session_key: client_session_key,
        server_session_key: server_session_key
    });
}