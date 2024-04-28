# Comparison of PAKE protocols for web authentication
This project aims to compare the performance of two Password Authenticated Key Exchange (PAKE) protocols for web authentication. The first is OPAQUE which is provided by the [`@cloudflare/opaque-ts`](https://www.npmjs.com/package/@cloudflare/opaque-ts) TypeScript library. The second is Owl, a new PAKE protocol which this project aims to implement in TypeScript. The Owl code is in a [separate repository](https://github.com/henry50/owl-ts). An express.js app will be used to demonstrate the protocols.

## Install
To clone the repository with `owl-ts`, run
```
git clone --recursive https://github.com/henry50/3rd-year-project.git
```

If you have already cloned the repository, run
```
git submodule update --init --recursive
```
to install `owl-ts`.

## Build
These commands assume your current directory is the root of the repository.

To build the demo, run
```
cd owl-ts
npm install
npm run build

cd ../demo
npm install
npm run build
```
## Configuration
The demonstration needs several environment variables to be set. The easiest way to set these is using a `.env` file.
```conf
# These are required by both protocols
DATABASE_URI=sqlite:demo.db
PORT=3000
SERVER_IDENTITY="localhost"

# These are required by OPAQUE
OPRF_SEED="..."
SERVER_AKE_PUBLIC_KEY="..."
SERVER_AKE_PRIVATE_KEY="..."
```

To generate a `.env` file with a random OPRF seed and AKE keypair, you can use the `generate_env.ts` file. If you have chosen a different OPAQUE config for the client and server, edit `generate_env.ts` to match.

To avoid accidentally overwriting an existing `.env` file, the script will not work if a `.env` file already exists. To generate a new `.env` file, run
```
cd demo
npx tsx generate_env.ts
```

## Run
Once configured, the demo can be run with
```
cd demo
npm run start
```
By default it will start on localhost:3000.

To run the benchmark, run
```
cd demo
npm run benchmark
```