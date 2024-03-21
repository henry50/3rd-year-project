import { Curves, OwlClient } from "owl-ts";
import { AlertType, showAlert } from "./common";

const cfg = {
    curve: Curves.P256,
    serverId: "localhost",
};

document
    .querySelector("form")!
    .addEventListener("submit", async function (event: Event) {
        event.preventDefault();
        (document.getElementById("submit") as HTMLButtonElement).disabled =
            true;
        try {
            const form = new FormData(event.target as HTMLFormElement);
            const username = form.get("username")!.toString().trim();
            const password = form.get("password")!.toString().trim();
            const confirm = form.get("confirm-password")!.toString().trim();
            if (password != confirm) {
                throw new Error("Passwords must match");
            }
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
        } catch (error: any) {
            // catch and show any errors
            showAlert(AlertType.Error, error.message);
        }
        (document.getElementById("submit") as HTMLButtonElement).disabled =
            false;
        return false;
    });
