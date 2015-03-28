'use strict';

var decode = forge.util.decode64;

var ALGO_MODE = 'AES-CBC';

function asymmetricDecrypt(encrypted, pem, passphrase) {
  var privateKey = forge.pki.decryptRsaPrivateKey(pem, passphrase);
  return privateKey.decrypt(decode(encrypted));
}

function symmetricDecrypt(key, iv, data) {
  var decipher = forge.cipher.createDecipher(ALGO_MODE, decode(key));
  decipher.start({ iv: decode(iv) });
  decipher.update(forge.util.createBuffer(decode(data)));
  decipher.finish();
  return decipher.output.data;
}

module.exports = function(encrypted, pem, passphrase) {
  var split = encrypted.split('|');
  var keyAndIV = asymmetricDecrypt(split[0], pem, passphrase).split('|');
  return symmetricDecrypt(keyAndIV[0], keyAndIV[1], split[1]);
}
