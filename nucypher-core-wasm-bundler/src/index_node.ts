import { webcrypto } from "node:crypto";

// Fixes Node.js ES module support
// See: https://docs.rs/getrandom/latest/getrandom/#nodejs-es-module-support
// @ts-ignore
globalThis.crypto = webcrypto;

export * from "./index_fat";
