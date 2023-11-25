
import {
    getOpaqueConfig,
    OpaqueID,
    OpaqueClient,
    KE2
// @ts-ignore
} from "./opaque_full.js" 


const cfg = getOpaqueConfig(OpaqueID.OPAQUE_P256)
const server_identity = 'localhost'

document.querySelector("form")!.addEventListener("submit", async function(event: Event){
    event.preventDefault();
    try{
    const form = new FormData(event.target as HTMLFormElement);
    const client_identity = form.get("username")!.toString().trim();
    const password = form.get("password")!.toString().trim();
    
    const client = new OpaqueClient(cfg);
    const ke1 = await client.authInit(password);
    if(ke1 instanceof Error){
        throw new Error("Failed to initialise login");
    }
    let response = await fetch("/login/login-init", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            username: client_identity,
            ke1: ke1.serialize()
        })
    });
    if(response.status != 200){
        throw new Error(await response.text());
    }
    let result = await response.json();

    const ke2 = KE2.deserialize(cfg, result.ke2);
    const authFinish = await client.authFinish(ke2, server_identity, client_identity);
    if(authFinish instanceof Error){
        throw authFinish;
    }
    const {ke3, session_key} = authFinish;
    response = await fetch("/login/login-finish", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            username: client_identity,
            ke3: ke3.serialize(),
            session_key: session_key
        })
    });
    if(response.status != 200){
        throw new Error(await response.text());
    }
    result = await response.json();

    window.location.replace("/restricted");
    } catch(error: any){
        console.error(error.message);
    }
    return false;
});