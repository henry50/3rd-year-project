import { OpaqueClient, OpaqueServer } from "@cloudflare/opaque-ts";
import { add } from "benny";
import { OwlClient, OwlServer } from "owl-ts";
import {
    opaqueConfig,
    opaqueServerConfig,
    owlConfig,
} from "./helpers/config.js";
import suite from "./helpers/suite.js";

export default () =>
    suite(
        "Test instantiation",
        add("Owl client instantiation", () => {
            new OwlClient(owlConfig);
        }),
        add("Owl server instantiation", () => {
            new OwlServer(owlConfig);
        }),
        add("OPAQUE client instantiation", () => {
            new OpaqueClient(opaqueConfig);
        }),
        add("OPAQUE server instantiation", () => {
            new OpaqueServer(...opaqueServerConfig);
        }),
    );
