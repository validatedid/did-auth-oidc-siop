/* eslint-disable @typescript-eslint/no-var-requires */
const path = require("path");
// eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
const nodeExternals = require("webpack-node-externals");

module.exports = {
  mode: "production",
  entry: "./src/index.ts",
  devtool: "inline-source-map",
  target: "node",
  // eslint-disable-next-line @typescript-eslint/no-unsafe-call
  externals: [nodeExternals()],
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
    path: path.resolve(__dirname, "dist"),
    filename: "validatedid-did-auth.js",
    library: "@validatedid/did-auth",
    libraryTarget: "umd",
    umdNamedDefine: true,
    globalObject: "this",
  },
};
