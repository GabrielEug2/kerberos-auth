
/**
 * Criptografia simétrica.
 * 
 * AES-128 com modo CBC e padding PKCS7 (Fernet)
 */
const fernet = require('fernet');

/**
 * Criptografa a string usando a chave especificada.
 * @param {string} str Dados a serem criptografados
 * @param {string} key Chave para a criptografia
 */
function encrypt(str, key) {
    return new fernet.Token({
        secret: new fernet.Secret(key)
    }).encode(str);
}

/**
 * Descriptografa a string usando a chave especificada.
 * @param {string} str Dados a serem descriptografados
 * @param {string} key Chave para a criptografia
 */
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