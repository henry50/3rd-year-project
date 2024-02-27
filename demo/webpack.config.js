import { dirname, resolve } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const entryPoints = [
    "common",
    "opaque_login",
    "opaque_register",
    "owl_login",
    "owl_register",
];

const configs = entryPoints.map((entryPoint) => ({
    entry: resolve(__dirname, "client", `${entryPoint}.ts`),
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: "ts-loader",
                exclude: /node_modules/,
            },
        ],
    },
    resolve: {
        extensions: [".tsx", ".ts", ".js"],
    },
    output: {
        filename: `${entryPoint}.js`,
        path: resolve(__dirname, "dist"),
    },
    mode: "production",
}));

export default configs;
