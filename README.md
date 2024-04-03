# Comparison of PAKE protocols for web authentication
This project aims to compare the performance of two Password Authenticated Key Exchange (PAKE) protocols for web authentication. The first is OPAQUE which is provided by the [`@cloudflare/opaque-ts`](https://www.npmjs.com/package/@cloudflare/opaque-ts) TypeScript library. The second is Owl, a new PAKE protocol which this project aims to implement in TypeScript. The Owl code is in a [separate repository](https://github.com/henry50/owl-ts). An express.js app will be used to demonstrate the protocols.

## Building
These commands assume your current directory is the root of the repository.

To build the demo, run
```
cd demo
npm install
npm run build
```

To run the demo, run
```
cd demo
npm run start
```

To run the benchmark, run
```
cd demo
npm run benchmark
```