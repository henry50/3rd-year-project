import { Curves, OwlClient } from "owl-ts";
import { AlertType, handleForm, showAlert } from "./common";

const cfg = {
    curve: Curves.P256,
    serverId: "localhost",
};

handleForm(async (username, password) => {
    // create registration values
    const client = new OwlClient(cfg);
    const regRequest = await client.register(username, password);
    let response = await fetch("/register/register-init", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
            username: username,
            data: regRequest.serialize(),
        }),
    });

    const type = response.ok ? AlertType.Success : AlertType.Error;
    showAlert(type, await response.text());
});
