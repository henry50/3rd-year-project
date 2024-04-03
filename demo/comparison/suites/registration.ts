import { OpaqueClient, OpaqueServer } from "@cloudflare/opaque-ts";
import { add } from "benny";
import { OwlClient, OwlServer } from "owl-ts";
import {
    opaqueConfig,
    opaqueServerConfig,
    owlConfig,
    serverIdentity,
} from "./helpers/config";
import { clientIdentity, password } from "./helpers/credentials";
import suite from "./helpers/suite";

export default () =>
    suite(
        "Test registration steps",
        add("Owl client registration", async () => {
            const owlClient = new OwlClient(owlConfig);
            return async () => {
                await owlClient.register(clientIdentity, password);
            };
        }),
        add("Owl server registration", async () => {
            const owlClient = new OwlClient(owlConfig);
            const owlServer = new OwlServer(owlConfig);
            const request = await owlClient.register(clientIdentity, password);
            return async () => {
                await owlServer.register(request);
            };
        }),
        add("OPAQUE client initial registration", async () => {
            const opaqueClient = new OpaqueClient(opaqueConfig);
            return async () => {
                await opaqueClient.registerInit(password);
            };
        }),
        add("OPAQUE server initial registration", async () => {
            const opaqueClient = new OpaqueClient(opaqueConfig);
            const opaqueServer = new OpaqueServer(...opaqueServerConfig);
            const request = await opaqueClient.registerInit(password);
            if (request instanceof Error) {
                throw request;
            }
            return async () => {
                await opaqueServer.registerInit(request, clientIdentity);
            };
        }),
        add("OPAQUE client final registration", async () => {
            const opaqueClient = new OpaqueClient(opaqueConfig);
            const opaqueServer = new OpaqueServer(...opaqueServerConfig);
            const initRequest = await opaqueClient.registerInit(password);
            if (initRequest instanceof Error) {
                throw initRequest;
            }
            const initResponse = await opaqueServer.registerInit(
                initRequest,
                clientIdentity,
            );
            if (initResponse instanceof Error) {
                throw initResponse;
            }
            return async () => {
                await opaqueClient.registerFinish(
                    initResponse,
                    serverIdentity,
                    clientIdentity,
                );
            };
        }),
    );
