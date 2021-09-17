var express = require("express");
var bookRouter = require("./book");

var app = express();

app.use("/books/", bookRouter);
module.exports = app;
