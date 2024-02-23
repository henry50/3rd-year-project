import { OwlClient, AuthInitResponse, DeserializationError, Curves } from "owl-ts";
import { AlertType, showAlert } from "./common";

const cfg = {
    curve: Curves.P256,
    serverId: "localhost"
}

document.querySelector("form")!.addEventListener("submit", async function(event: Event){
    // prevent form submission
    event.preventDefault();
    (document.getElementById("submit") as HTMLButtonElement).disabled = true;
    try{
    const form = new FormData(event.target as HTMLFormElement);
    const username = form.get("username")!.toString().trim();
    const password = form.get("password")!.toString().trim();
    
    const client = new OwlClient(cfg);
    const initRequest = await client.authInit(username, password);
    let response = await fetch("/login/login-init", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            username: username,
            init: initRequest.serialize()
        })
    });
    if(response.status != 200){
        throw new Error(await response.text());
    }
    let result = await response.json();

    const initResponse = AuthInitResponse.deserialize(result, cfg);
    if(initResponse instanceof DeserializationError){
        throw initResponse;
    }

    const finish = await client.authFinish(initResponse);
    if(finish instanceof Error){
        throw finish;
    }
    const {key, finishRequest} = finish;

    response = await fetch("/login/login-finish", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            username: username,
            finish: finishRequest.serialize()
        })
    });

    const type = response.status == 200 ? AlertType.Success : AlertType.Error;
    showAlert(type, await response.text());

    // catch any error which might occur
    } catch(error: any){
        showAlert(AlertType.Error, error.message);
    }
    (document.getElementById("submit") as HTMLButtonElement).disabled = false;
    // prevent form submission
    return false;
});