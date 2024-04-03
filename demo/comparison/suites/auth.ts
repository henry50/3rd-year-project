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
        "Test authorisation steps",
        add("Owl client authInit", async () => {
            const owlClient = new OwlClient(owlConfig);
            return async () => {
                await owlClient.authInit(clientIdentity, password);
            };
        }),
        add("Owl server authInit", async () => {
            const owlClient = new OwlClient(owlConfig);
            const owlServer = new OwlServer(owlConfig);
            const regRequest = await owlClient.register(
                clientIdentity,
                password,
            );
            const regResponse = await owlServer.register(regRequest);
            const request = await owlClient.authInit(clientIdentity, password);
            return async () => {
                await owlServer.authInit(clientIdentity, request, regResponse);
            };
        }),
        add("Owl client authFinish", async () => {
            const owlClient = new OwlClient(owlConfig);
            const owlServer = new OwlServer(owlConfig);
            const regRequest = await owlClient.register(
                clientIdentity,
                password,
            );
            const regResponse = await owlServer.register(regRequest);
            const request = await owlClient.authInit(clientIdentity, password);
            const response = await owlServer.authInit(
                clientIdentity,
                request,
                regResponse,
            );
            if (response instanceof ZKPVerificationFailure) {
                throw response;
            }
            return async () => {
                await owlClient.authFinish(response.response);
            };
        }),
        add("Owl server authFinish", async () => {
            const owlClient = new OwlClient(owlConfig);
            const owlServer = new OwlServer(owlConfig);
            const regRequest = await owlClient.register(
                clientIdentity,
                password,
            );
            const regResponse = await owlServer.register(regRequest);
            const request = await owlClient.authInit(clientIdentity, password);
            const response = await owlServer.authInit(
                clientIdentity,
                request,
                regResponse,
            );
            if (response instanceof ZKPVerificationFailure) {
                throw response;
            }
            const finish = await owlClient.authFinish(response.response);
            if (finish instanceof ZKPVerificationFailure) {
                throw finish;
            }
            return async () => {
                await owlServer.authFinish(
                    clientIdentity,
                    finish.finishRequest,
                    response.initial,
                );
            };
        }),
        add("OPAQUE client authInit", async () => {
            const opaqueClient = new OpaqueClient(opaqueConfig);
            return async () => {
                await opaqueClient.authInit(password);
            };
        }),
        add("OPAQUE server authInit", async () => {
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
            const request = await opaqueClient.authInit(password);
            if (request instanceof Error) {
                throw request;
            }
            return async () => {
                await opaqueServer.authInit(
                    request,
                    regFinish.record,
                    clientIdentity,
                    clientIdentity,
                );
            };
        }),
        add("OPAQUE client authFinish", async () => {
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
            return async () => {
                await opaqueClient.authFinish(
                    response.ke2,
                    serverIdentity,
                    clientIdentity,
                );
            };
        }),
        add("OPAQUE server authFinish", async () => {
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
            return () => {
                opaqueServer.authFinish(finish.ke3, response.expected);
            };
        }),
    );
