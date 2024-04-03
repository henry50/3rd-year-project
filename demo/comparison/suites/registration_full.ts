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
        "Test full registration",
        add("Owl full registration", async () => {
            const owlClient = new OwlClient(owlConfig);
            const owlServer = new OwlServer(owlConfig);
            return async () => {
                const request = await owlClient.register(
                    clientIdentity,
                    password,
                );
                await owlServer.register(request);
            };
        }),
        add("OPAQUE full registration", async () => {
            const opaqueClient = new OpaqueClient(opaqueConfig);
            const opaqueServer = new OpaqueServer(...opaqueServerConfig);
            return async () => {
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
                await opaqueClient.registerFinish(
                    initResponse,
                    serverIdentity,
                    clientIdentity,
                );
            };
        }),
    );
