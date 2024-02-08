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
    
    const client = new OwlClient(cfg);
    const {X1, X2, PI1, PI2} = await client.authInit(username, password);
    let response = await fetch("/login/login-init", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({
            username: username,
            X1: X1.toString(16),
            X2: X2.toString(16),
            PI1: {
                h: PI1.h.toString(16),
                r: PI1.r.toString(16)
            },
            PI2: {
                h: PI2.h.toString(16),
                r: PI2.r.toString(16)
            }
        })
    });
    if(response.status != 200){
        throw new Error(await response.text());
    }
    let result = await response.json();
    console.log(result);

    // const ke2 = KE2.deserialize(cfg, result.ke2);
    // const authFinish = await client.authFinish(ke2, server_identity, client_identity);
    // if(authFinish instanceof Error){
    //     throw authFinish;
    // }
    // const {ke3, session_key} = authFinish;
    // response = await fetch("/login/login-finish", {
    //     method: "POST",
    //     headers: {"Content-Type": "application/json"},
    //     body: JSON.stringify({
    //         username: client_identity,
    //         ke3: ke3.serialize(),
    //         session_key: session_key
    //     })
    // });
    // if(response.status != 200){
    //     throw new Error(await response.text());
    // }
    // result = await response.json();

    // window.location.replace("/restricted");
    } catch(error: any){
        console.error(error.message);
    }
    return false;
});