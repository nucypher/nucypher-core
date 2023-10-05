export * from "./index_core.js";
import wasm from "./pkg/nucypher_core_wasm_bg.wasm";
import { setWasmInit } from "./wasm.js";

// @ts-ignore
setWasmInit(() => wasm());
