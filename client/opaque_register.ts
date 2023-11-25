
import {
    getOpaqueConfig,
    OpaqueID,
    OpaqueClient,
    RegistrationResponse
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
    const confirm = form.get("confirm-password")!.toString().trim();
    if(password != confirm){
        throw new Error("Passwords must match");
    }
    // create client and attempt registration
    const client = new OpaqueClient(cfg);
    const init = await client.registerInit(password);
    if(init instanceof Error){
        throw new Error("Registration initiation failed");
    }
    let response = await fetch("/register/register-init", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            username: client_identity,
            init: init.serialize()
        })
    });
    if(response.status != 200){
        throw new Error(await response.text());
    }
    let result = await response.json();
    const envelope = await RegistrationResponse.deserialize(cfg, result.envelope);
    const registration = await client.registerFinish(envelope, server_identity, client_identity);
    if(registration instanceof Error){
        throw new Error("Sealing of registration envelope failed");
    }
    const record = registration.record;
    
    response = await fetch("/register/register-finish", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            username: client_identity,
            record: record.serialize()
        })
    });
    if(response.status != 200){
        throw new Error(await response.text());
    }
    result = response.json();
    console.log(`Success! ${result.message}`);
    window.location.replace("/login");
    } catch(error: any){
        console.error(error.message);
    }
    return false;
});