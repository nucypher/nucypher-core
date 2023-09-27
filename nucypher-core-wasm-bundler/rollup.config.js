import typescript from "@rollup/plugin-typescript";
import { wasm } from "@rollup/plugin-wasm";
import path from "path";
import fs from "fs";

const outDir = (fmt, env) => {
  if (env === "node") {
    return `node`;
  } else {
    return `${fmt}${env === "slim" ? "-slim" : ""}`;
  }
};

const rolls = (fmt, env) => ({
  input: `src/index_${env}.ts`,
  output: {
    dir: `dist`,
    format: fmt,
    entryFileNames:
      outDir(fmt, env) + `/[name].` + (fmt === "cjs" ? "cjs" : "js"),
    name: "@nucypher/nucypher-core-wasm",
  },
  external: ["node:crypto"],
  plugins: [
    env !== "slim" &&
      wasm(
        env === "node"
          ? {
              maxFileSize: 0,
              targetEnv: "node",
              publicPath: "../",
              fileName: "[name][extname]",
            }
          : { targetEnv: "auto-inline" },
      ),
    typescript({
      target: fmt === "es" ? "ES2022" : "ES2017",
      outDir: `dist/${outDir(fmt, env)}`,
      rootDir: "src",
    }),
    {
      name: "copy-pkg",
      resolveImportMeta: () => `""`,
      generateBundle() {
        fs.mkdirSync(`./dist/types/pkg`, { recursive: true });
        fs.copyFileSync(
          path.resolve("./src/pkg/nucypher_core_wasm.d.ts"),
          path.resolve("./dist/types/pkg/nucypher_core_wasm.d.ts"),
        );
      },
    },
  ],
});

export default [
  rolls("umd", "fat"),
  rolls("es", "fat"),
  rolls("cjs", "fat"),
  rolls("cjs", "node"),
  // TODO: Slim build is not supported ATM
  // rolls("es", "slim"),
  // rolls("cjs", "slim"),
];
