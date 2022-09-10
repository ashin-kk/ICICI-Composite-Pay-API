const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// ENCRYPT THE TRSANCTION DATA
module.exports.iciciDataEncrypt = async (data, encriptionKey, iv) => {
    try {
        const algorithm = 'aes-128-cbc';
        const key = encriptionKey;

        const cipher = crypto.createCipheriv(algorithm, key, iv);
        let encrypted = cipher.update(data, 'utf8', 'base64');
        encrypted += cipher.final('base64');

        return encrypted;
    } catch (err) {
        console.log(err);
        return false;
    }
};
// DECRYPT THE TRSANCTION DATA
module.exports.iciciDataDecrypt = async (encriptedData, decriptionKey) => {
    try {
        const algorithm = 'aes-128-cbc';
        const key = decriptionKey;
        const iv = encriptedData.slice(0, 16);

        const decipher = crypto.createDecipheriv(algorithm, key, iv);
        const encrypted = encriptedData;
        let decrypted = decipher.update(encrypted, 'base64', 'utf8');
        decrypted += decipher.final('utf8');

        // Using this because ICICI Response Data having issue
        const validCharacters = decrypted.split('{').slice(-1)[0];
        const responseData = '{' + validCharacters;

        return responseData;
    } catch (error) {
        console.log(error);
        return false;
    }
};

// ENCRYPT THE ENCRYPTION KEY WITH ICICI PUBLIC KEY
module.exports.iciciKeyEncrypt = async (sesionKey) => {
    try {
        const filePath = path.resolve('./.icici_public_key.env');
        const publicKey = fs.readFileSync(filePath, 'utf8');
        const buffer = Buffer.from(sesionKey, 'utf8');
        const encrypted = crypto.publicEncrypt(
            { key: publicKey, padding: crypto.constants.RSA_PKCS1_PADDING },
            buffer
        );
        const encryptedKey = encrypted.toString('base64');

        return encryptedKey;
    } catch (error) {
        console.log(error);
        return false;
    }
};
// DECRYPT THE ENCRYPTION KEY WITH CLIENT PRIVATE KEY
module.exports.iciciKeyDecrypt = async (encryptedKey) => {
    try {
        const filePath = path.resolve('./.my_private_key.env');
        const privateKey = fs.readFileSync(filePath, 'utf8');
        const buffer = Buffer.from(encryptedKey, 'base64');
        const decrypted = crypto.privateDecrypt(
            { key: privateKey, padding: crypto.constants.RSA_PKCS1_PADDING },
            buffer
        );

        const sesionKey = decrypted.toString('utf8');
        return sesionKey;
    } catch (error) {
        console.log(error);
        return false;
    }
};
