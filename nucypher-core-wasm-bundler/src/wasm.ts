import init, { InitInput } from "./pkg/nucypher_core_wasm.js";

export * from "./pkg/nucypher_core_wasm.js";

let wasmInit: (() => InitInput) | undefined = undefined;

export const setWasmInit = (arg: () => InitInput) => {
  wasmInit = arg;
};

let initialized: Promise<void> | undefined = undefined;

export const initialize = async (wasm?: InitInput) => {
  if (initialized === undefined) {
    //@ts-ignore
    const loadModule = wasm ?? wasmInit();
    initialized = init(loadModule).then(() => void 0);
  }

  await initialized;
};
