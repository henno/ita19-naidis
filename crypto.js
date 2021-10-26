const {JWS, JWK} = require("node-jose");
const fs = require("fs");
const {join} = require("path");
const jwt = require("jsonwebtoken");
const jwkToPem = require("jwk-to-pem");
const {sendGetRequest} = require("./middlewares");

exports.getToken = async function (dataToBeSigned, key) {
    return await JWS.createSign({
        compact: true,
        jwk: key,
        fields: {typ: 'jwt'}
    }, key).update(JSON.stringify(dataToBeSigned)).final();
}
exports.getKeystore = async function () {
    const keystore = JWK.createKeyStore();
    if (!fs.existsSync(keystoreFile)) {
        if (!fs.existsSync(certDir)) {
            fs.mkdirSync(certDir)
        }
        console.log('generate keystore')
        await keystore.generate('RSA', 2048, {alg: 'RS256', use: 'sig'})
        fs.writeFileSync(keystoreFile, JSON.stringify(keystore.toJSON(true)))
    } else {
        console.log('import keystore')
        const ks = fs.readFileSync(join('.cert', 'keystore.json'))
        return await JWK.asKeyStore(ks.toString())
    }
}

exports.getSigningKey = async function () {

    // Get keystore
    const keystore = await exports.getKeystore();

    // Use first sig key
    return keystore.all({use: 'sig'})[0]
}

exports.createSignedTransaction = async function (input) {

    try {
        return await exports.getToken(input, await exports.getSigningKey())
    } catch (err) {
        console.error('Error reading private key' + err)
        throw Error('Error reading private key' + err)
    }
}

exports.verifySignature = async function (jwtString, publicKey) {
    return !!jwt.verify(jwtString, publicKey)
}

exports.getPublicKey = async function (jwksUrl) {
    const jwks = await sendGetRequest(jwksUrl)
    const signingKey = await exports.getSigningKey();
    return jwkToPem(signingKey.toJSON())
}