import {
    KE2,
    OpaqueClient,
    OpaqueID,
    getOpaqueConfig,
} from "@cloudflare/opaque-ts";
import { AlertType, handleForm, showAlert } from "./common";

const cfg = getOpaqueConfig(OpaqueID.OPAQUE_P256);
const server_identity = "localhost";

handleForm(async (username, password) => {
    const client = new OpaqueClient(cfg);
    const ke1 = await client.authInit(password);
    if (ke1 instanceof Error) {
        throw new Error("Failed to initialise login");
    }
    let response = await fetch("/login/login-init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username: username,
            ke1: ke1.serialize(),
        }),
    });
    if (!response.ok) {
        throw new Error(await response.text());
    }
    let result = await response.json();

    const ke2 = KE2.deserialize(cfg, result.ke2);
    const authFinish = await client.authFinish(ke2, server_identity, username);
    if (authFinish instanceof Error) {
        throw authFinish;
    }
    const { ke3, session_key } = authFinish;
    response = await fetch("/login/login-finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username: username,
            ke3: ke3.serialize(),
            session_key: session_key,
        }),
    });
    if (!response.ok) {
        throw new Error(await response.text());
    }
    result = await response.json();
    showAlert(AlertType.Success, result.message);
});
