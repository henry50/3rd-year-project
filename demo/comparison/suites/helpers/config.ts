import {
    AKEExportKeyPair,
    Config,
    OpaqueID,
    getOpaqueConfig,
} from "@cloudflare/opaque-ts";
import { Curves } from "owl-ts";

export const serverIdentity = "localhost";

export const owlConfig = {
    curve: Curves.P256,
    serverId: serverIdentity,
};

export const opaqueConfig = getOpaqueConfig(OpaqueID.OPAQUE_P256);

const oprfSeed = opaqueConfig.prng.random(opaqueConfig.hash.Nh);
const AKEKeyPair = await opaqueConfig.ake.generateAuthKeyPair();
export const opaqueServerConfig: [Config, number[], AKEExportKeyPair, string] =
    [opaqueConfig, oprfSeed, AKEKeyPair, serverIdentity];
