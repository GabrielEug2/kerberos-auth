
const fernet = require('fernet');

function encrypt(str, key) {
    return new fernet.Token({
        secret: new fernet.Secret(key)
    }).encode(str);
}

function decrypt(str, key) {
    return new fernet.Token({
        token: str,
        secret: new fernet.Secret(key),
        ttl: 0
    }).decode();
}

module.exports = {
    encrypt: encrypt,
    decrypt: decrypt
}