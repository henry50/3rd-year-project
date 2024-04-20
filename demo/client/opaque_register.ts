import {
    getOpaqueConfig,
    OpaqueID,
    OpaqueClient,
    RegistrationResponse,
} from "@cloudflare/opaque-ts";
import { AlertType, handleForm, showAlert } from "./common";

const cfg = getOpaqueConfig(OpaqueID.OPAQUE_P256);
const server_identity = "localhost";

handleForm(async (username, password) => {
    // create client and attempt registration
    const client = new OpaqueClient(cfg);
    const init = await client.registerInit(password);
    if (init instanceof Error) {
        throw new Error("Registration initiation failed");
    }
    let response = await fetch("/register/register-init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username: username,
            init: init.serialize(),
        }),
    });
    if (!response.ok) {
        throw new Error(await response.text());
    }
    let result = await response.json();
    const envelope = RegistrationResponse.deserialize(cfg, result.envelope);
    const registration = await client.registerFinish(
        envelope,
        server_identity,
        username,
    );
    if (registration instanceof Error) {
        throw new Error("Sealing of registration envelope failed");
    }
    const record = registration.record;

    response = await fetch("/register/register-finish", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username: username,
            record: record.serialize(),
        }),
    });
    if (!response.ok) {
        throw new Error(await response.text());
    }
    result = await response.json();
    showAlert(AlertType.Success, result.message);
});
