const FCM = require('fcm-node');


const serverKey = process.env.serverKey;
const fcm = new FCM(serverKey);

module.exports = fcm;