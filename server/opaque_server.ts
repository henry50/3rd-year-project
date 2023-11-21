import {
    getOpaqueConfig,
    OpaqueID,
    RegistrationRecord,
    CredentialFile,
    RegistrationRequest,
    OpaqueServer
} from "@cloudflare/opaque-ts"
import { Request, Response } from "express";
import { validate } from "jsonschema";
import { User } from "./database.js";

const cfg = getOpaqueConfig(OpaqueID.OPAQUE_P256);

function fromHex(x: string): number[] {
    return Array.from(Buffer.from(x, 'hex'))
}

const env = process.env;

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
        .findOne({where: {username: credential_identifier}})
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
