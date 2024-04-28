import { OpaqueID, getOpaqueConfig } from "@cloudflare/opaque-ts";
import * as fs from "fs";

const template = (oprf_seed: string, ake_pub: string, ake_prv: string) => `\
DATABASE_URI=sqlite:example.db
PORT=3000
OPRF_SEED="${oprf_seed}"
SERVER_AKE_PUBLIC_KEY="${ake_pub}"
SERVER_AKE_PRIVATE_KEY="${ake_prv}"
SERVER_IDENTITY="localhost"`;

function toHexString(arr: number[]) {
    return Array.from(arr, function (byte) {
        return ("0" + (byte & 0xff).toString(16)).slice(-2);
    }).join("");
}

async function main() {
    if (fs.existsSync(".env")) {
        console.error("Cannot create .env, it already exists!");
        return;
    }
    // CHANGE THIS TO YOUR OPAQUE CONFIG!!! //
    const config = getOpaqueConfig(OpaqueID.OPAQUE_P256);
    // ------------------------------------ //
    const oprf_seed = config.prng.random(config.hash.Nh);
    const { private_key, public_key } = await config.ake.generateAuthKeyPair();
    const env = template(
        toHexString(oprf_seed),
        toHexString(public_key),
        toHexString(private_key),
    );
    fs.writeFile(".env", env, (err) => {
        if (err) throw err;
        console.log(".env generated successfully");
    });
}

main();
