import commonjs from "@rollup/plugin-commonjs"
import { nodeResolve } from "@rollup/plugin-node-resolve"
import fs from "fs"
import cleanup from "rollup-plugin-cleanup"
import typescript from "@rollup/plugin-typescript"

const pkg = JSON.parse(fs.readFileSync("./package.json", "utf8"))
const banner = `/**
 * @module ${pkg.name}
 * @version ${pkg.version}
 * @file ${pkg.description}
 * @copyright Ethereum Foundation ${new Date().getFullYear()}
 * @license ${pkg.license}
 * @see [Github]{@link ${pkg.homepage}}
*/`

export default {
    input: "src/index.ts",
    output: [
        { file: pkg.exports["."].require, format: "cjs", banner },
        { file: pkg.exports["."].default, format: "es", banner }
    ],
    external: Object.keys(pkg.dependencies),
    plugins: [
        typescript({ tsconfig: "./build.tsconfig.json" }),
        commonjs(),
        nodeResolve({
            preferBuiltins: true
        }),
        cleanup({ comments: "jsdoc" })
    ]
}
