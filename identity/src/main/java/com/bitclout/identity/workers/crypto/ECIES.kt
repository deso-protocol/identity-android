package com.bitclout.identity.workers.crypto

import android.os.Build
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.*
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec


object ECIES {

    private const val SECP256K1 = "secp256k1"
    private const val EC = "EC"


    fun randomBytes(number: Int): ByteArray {
        val byteArray = ByteArray(number)
        when {
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.O -> {
                SecureRandom.getInstanceStrong().nextBytes(byteArray)
            }
            else -> SecureRandom().nextBytes(byteArray)
        }
        return byteArray
    }


    /**
    Obtain the private elliptic curve SECP256K1 key from a provided byte array
     */
    fun getECPrivateKeyFromByteArray(byteArray: ByteArray): org.bouncycastle.jce.interfaces.ECPrivateKey {
        val ecParameterSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")
        val privateKeySpec = ECPrivateKeySpec(BigInteger(byteArray), ecParameterSpec)
        val keyFactory = KeyFactory.getInstance(EC)
        return keyFactory.generatePrivate(privateKeySpec) as org.bouncycastle.jce.interfaces.ECPrivateKey
    }

    /**
    Obtain the public elliptic curve SECP256K1 key from a private
     */
    fun getPublicKeyFromECPrivateKey(privateKey: org.bouncycastle.jce.interfaces.ECPrivateKey): PublicKey {
        val keyFactory: KeyFactory = KeyFactory.getInstance(EC)
        val spec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(SECP256K1)
        val Q: ECPoint = spec.g.multiply(privateKey.d)
        return keyFactory.generatePublic(ECPublicKeySpec(Q, spec))
    }

    /**
    Obtain a elliptic curve key pair using secp256k1
     */
    fun getECKeyPair(): Pair<ECPrivateKey, ECPublicKey> {
        val kpg: KeyPairGenerator = KeyPairGenerator.getInstance(EC)
        kpg.initialize(ECGenParameterSpec(SECP256K1))
        val keyPair: KeyPair = kpg.generateKeyPair()
        val privateKey: ECPrivateKey = keyPair.private as ECPrivateKey
        val publicKey: ECPublicKey = keyPair.public as ECPublicKey
        return Pair(privateKey, publicKey)
    }


    /**
    Decrypt serialised AES-128-CTR
    Using ECDH shared secret KDF
     */
    fun decryptShared(sharedPx: ByteArray, encrypted: ByteArray): ByteArray {
//        val sharedPrivateKey = kdf(secret: sharedPx, outputLength: 32)
//        return try decrypt(privateKey: sharedPrivateKey, encrypted: encrypted)
        return ByteArray(0)
    }

    /**
    Decrypt serialised AES-128-CTR
     */
    private fun decrypt(privateKey: ByteArray, encrypted: ByteArray): ByteArray {
//        val metaLength = 1 + 64 + 16 + 32
//        if encrypted.count > metaLength, encrypted[0] >= 2, encrypted[0] <= 4 else { throw CryptoError.invalidCipherText }
//
//        // deserialize
//        val ephemPublicKey = encrypted.slice(from: 0, length: 65)
//        val cipherTextLength = encrypted.count - metaLength
//        val iv = encrypted.slice(from: 65, length: 65 + 16)
//        val cipherAndIv = encrypted.slice(from: 65, length: 65 + 16 + cipherTextLength)
//        val cipherText = cipherAndIv.slice(from: 16)
//        val msgMac = encrypted.slice(from: 65 + 16 + cipherTextLength)
//
//        // check HMAC
//        let px = try derive(privateKeyA: privateKey, publicKeyB: ephemPublicKey)
//            let hash = kdf(secret: px, outputLength: 32)
//            let encryptionKey = hash.slice(from: 0, length: 16)
//            let macKey = Hash.sha256(hash.slice(from: 16))
//            guard try hmacSha256Sign(key: macKey, msg: cipherAndIv) == msgMac else { throw CryptoError.incorrectMAC }
//
//                return try legacy ?
//                    aesCtrDecryptLegacy(iv: iv, key: encryptionKey, data: cipherText) :
//                    aesCtrDecrypt(iv: iv, key: encryptionKey, data: cipherText)
        return ByteArray(0)
    }

    /**
    Encrypt AES-128-CTR and serialise as in Parity
    Serialization: <ephemPubKey><IV><CipherText><HMAC>
     */
    fun encrypt(publicKeyTo: ByteArray, msg: ByteArray): ByteArray {
//        val (ephemeralPrivateKey, ephemeralPublicKey) = getECKeyPair()
        val ephemeralPrivateKey = getECPrivateKeyFromByteArray(randomBytes(32))
        val ephemeralPublicKey = getPublicKeyFromECPrivateKey(ephemeralPrivateKey)
//        val cipherText = performAesCtr(,,,Cipher.ENCRYPT_MODE)


        //From Swift Impl
//        let ephemPrivateKey = try ephemPrivateKey ?? randomBytes(count: 32)
//            let ephemPublicKey = try getPublicKey(from: ephemPrivateKey)
//
//                let sharedPx = try derive(privateKeyA: ephemPrivateKey, publicKeyB: publicKeyTo)
//                    let hash =  kdf(secret: sharedPx, outputLength: 32)
//                    let iv = try iv ?? randomBytes(count: 16)
//                        let encryptionKey = hash.slice(from: 0, length: 16)
//
//                        let macKey = Hash.sha256(hash.slice(from: 16))
//
//                        let cipherText = try legacy ?
//                            aesCtrEncryptLegacy(iv: iv, key: encryptionKey, data: msg) :
//                            aesCtrEncrypt(iv: iv, key: encryptionKey, data: msg)
//
//                            let dataToMac = iv + cipherText
//                            let hmac = try hmacSha256Sign(key: macKey, msg: dataToMac)
//
//                                return ephemPublicKey + iv + cipherText + hmac
//                            }
        return ByteArray(0)
    }

    // TODO: check NoPadding is correct.
    private fun performAesCtr(
        iv: ByteArray,
        key: Key,
        data: ByteArray,
        encryptDecryptMode: Int
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(encryptDecryptMode, key, IvParameterSpec(iv))
        val firstChunk = cipher.update(data)
        val secondChunk: ByteArray = cipher.doFinal()
        return firstChunk + secondChunk
    }
}