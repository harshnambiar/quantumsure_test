const path = require("path");
const HtmlWebpackPlugin = require("html-webpack-plugin");
const webpack = require('webpack');

module.exports = {
  entry: "./src/index.js",
  optimization: {
    minimize: false,
    runtimeChunk: false,
  },
  output: {
    path: path.resolve(__dirname, "dist"),
    filename: "main.js",
    chunkFilename: 'main.[id].js',
    clean: true,
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: 'src/index.html'
    }),
    new webpack.ProvidePlugin({
          process: 'process/browser',
        })
  ],
  module: {
    rules: [
      {
        test: /\.html$/i,
        loader: "html-loader",
      },
    ],
    
  },
  resolve: {
    fallback: {
      
      "assert": false,
      "fs": false,
      "vm": false,
      "process": require.resolve('process/browser'),
      "path": require.resolve('path-browserify'),
      "crypto": require.resolve('crypto-browserify'),
      "buffer": require.resolve('buffer/'),
      "stream": require.resolve('stream-browserify')
    } 
  },
  devServer: {
    static: {
      directory: path.resolve(__dirname, "dist"),
    },
    compress: false,
    port: 3000,
  },
  performance: {
    hints: false,
    maxEntrypointSize: 512000,
    maxAssetSize: 512000,
  },
};
