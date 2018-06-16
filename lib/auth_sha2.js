var crypto = require('crypto');
var Buffer = require('safe-buffer').Buffer;
var xor = require('./auth_41').xor;

function sha256(msg) {
  var hash = crypto.createHash('sha256');
  hash.update(msg);
  return hash.digest();
}

function calculateToken(password, scramble) {
  if (!password) {
    return Buffer.alloc(0);
  }
  var stage1 = sha256((Buffer.from(password, 'utf8')).toString('binary'));
  var stage2 = sha256(stage1);
  var stage3 = sha256(stage2 + scramble.toString('binary'));
  return xor(stage1, stage3);
};

module.exports.calculateToken = calculateToken;
