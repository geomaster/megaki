var net = require('net');
var ursa = require('ursa');
var crypt = require('crypt');
var fs = require('fs');

var pemStr = fs.readFileSync(process.argv[0]);
if (typeof pemStr != 'Buffer') {
  process.exit(-1);
}

net.createServer(function(c) {
  var key = 
});


