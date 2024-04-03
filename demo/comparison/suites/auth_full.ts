import { OpaqueClient, OpaqueServer } from "@cloudflare/opaque-ts";
import { add } from "benny";
import { OwlClient, OwlServer, ZKPVerificationFailure } from "owl-ts";
import {
    opaqueConfig,
    opaqueServerConfig,
    owlConfig,
    serverIdentity,
} from "./helpers/config.js";
import { clientIdentity, password } from "./helpers/credentials.js";
import suite from "./helpers/suite.js";

export default () =>
    suite(
        "Test full authorisation",
        add("Owl full authorisation", async () => {
            const owlClient = new OwlClient(owlConfig);
            const owlServer = new OwlServer(owlConfig);
            const regRequest = await owlClient.register(
                clientIdentity,
                password,
            );
            const regResponse = await owlServer.register(regRequest);
            return async () => {
                const initRequest = await owlClient.authInit(
                    clientIdentity,
                    password,
                );
                const initResponse = await owlServer.authInit(
                    clientIdentity,
                    initRequest,
                    regResponse,
                );
                if (initResponse instanceof ZKPVerificationFailure) {
                    throw initResponse;
                }
                const finishRequest = await owlClient.authFinish(
                    initResponse.response,
                );
                if (finishRequest instanceof ZKPVerificationFailure) {
                    throw finishRequest;
                }
                await owlServer.authFinish(
                    clientIdentity,
                    finishRequest.finishRequest,
                    initResponse.initial,
                );
            };
        }),
        add("OPAQUE full authorisation", async () => {
            const opaqueClient = new OpaqueClient(opaqueConfig);
            const opaqueServer = new OpaqueServer(...opaqueServerConfig);
            const regRequest = await opaqueClient.registerInit(password);
            if (regRequest instanceof Error) {
                throw regRequest;
            }
            const regResponse = await opaqueServer.registerInit(
                regRequest,
                clientIdentity,
            );
            if (regResponse instanceof Error) {
                throw regResponse;
            }
            const regFinish = await opaqueClient.registerFinish(
                regResponse,
                serverIdentity,
                clientIdentity,
            );
            if (regFinish instanceof Error) {
                throw regFinish;
            }
            return async () => {
                const request = await opaqueClient.authInit(password);
                if (request instanceof Error) {
                    throw request;
                }
                const response = await opaqueServer.authInit(
                    request,
                    regFinish.record,
                    clientIdentity,
                    clientIdentity,
                );
                if (response instanceof Error) {
                    throw response;
                }
                const finish = await opaqueClient.authFinish(
                    response.ke2,
                    serverIdentity,
                    clientIdentity,
                );
                if (finish instanceof Error) {
                    throw finish;
                }
                opaqueServer.authFinish(finish.ke3, response.expected);
            };
        }),
    );
