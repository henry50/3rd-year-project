import { dirname, resolve } from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const entryPoints = [
    "opaque_login",
    "opaque_register",
    "owl_login",
    "owl_register"
];

// from https://github.com/webpack/webpack/issues/11467#issuecomment-808618999
// fixes "The request ... failed to resolve only because it was resolved as fully specified" error
const webpack5esmInteropRule = {
    test: /\.m?js/,
    resolve: {
      fullySpecified: false
    }
};
  

const configs = entryPoints.map((entryPoint) => (
    {
        entry: resolve(__dirname, "client", `${entryPoint}.ts`),
        module: {
            rules: [
                {
                    test: /\.tsx?$/,
                    use: 'ts-loader',
                    exclude: /node_modules/
                },
                webpack5esmInteropRule
            ]
        },
        resolve: {
            extensions: [".tsx", ".ts", ".js"]
        },
        output: {
            filename: `${entryPoint}.js`,
            path: resolve(__dirname, "dist")
        },
        mode: "production"
    }
));


export default configs;