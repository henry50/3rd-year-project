import auth from "./suites/auth.js";
import auth_full from "./suites/auth_full.js";
import instantiation from "./suites/instantiation.js";
import registration from "./suites/registration.js";
import registration_full from "./suites/registration_full.js";

const main = async () => {
    instantiation();
    await registration();
    await registration_full();
    await auth();
    await auth_full();
};

main();
