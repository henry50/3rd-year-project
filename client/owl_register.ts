import OwlClient from "./owl_client";

const cfg = {
    p: "0xfd7f53811d75122952df4a9c2eece4e7f611b7523cef4400c31e3f80b6512669455d402251fb593d8d58fabfc5f5ba30f6cb9b556cd7813b801d346ff26660b76b9950a5a49f9fe8047b1022c24fbba9d7feb7c61bf83b57e7c6a8a6150f04fb83f6d3c51ec3023554135a169132f675f3ae2b61d72aeff22203199dd14801c7",
    q: "0x9760508f15230bccb292b982a2eb840bf0581cf5",
    g: "0xf7e1a085d69b3ddecbbcab5c36b857b97994afbbfa3aea82f9574c0b3d0782675159578ebad4594fe67107108180b449167123e84c281613b7cf09328cc8a6e13c167a8b547c8d28e0a3ae1e2bb3a675916ea37f0bfa213562f1fb627a01243bcca4f1bea8519089a883dfe15ae59f06928b665e807b552564014c3bfecf492a",
    serverId: "localhost"
}

document.querySelector("form")!.addEventListener("submit", async function(event: Event){
    event.preventDefault();
    try{
    const form = new FormData(event.target as HTMLFormElement);
    const username = form.get("username")!.toString().trim();
    const password = form.get("password")!.toString().trim();
    const confirm = form.get("confirm-password")!.toString().trim();
    if(password != confirm){
        throw new Error("Passwords must match");
    }
    // create registration values
    const client = new OwlClient(cfg);
    const regRequest = await client.register(username, password);
    let response = await fetch("/register/register-init", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: regRequest
    });
    if(response.status != 200){
        throw new Error(await response.text());
    }
    let result = await response.json();
    window.location.replace("/login");
    } catch(error: any){
        console.error(error.message);
    }
    return false;
});