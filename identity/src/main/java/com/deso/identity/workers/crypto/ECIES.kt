package com.deso.identity.workers.crypto

import com.deso.identity.models.CryptoException
import org.bouncycastle.asn1.sec.ECPrivateKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.ECPointUtil
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.math.ec.ECPoint
import java.math.BigInteger
import java.security.*
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


object ECIES {

    init {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        Security.addProvider(BouncyCastleProvider())
    }

    const val SECP256K1 = "secp256k1"
    private const val HMACSHA256 = "HmacSHA256"
    private val ecSpec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(SECP256K1)
    private const val useCompressedPointEncoding: Boolean = false
    private val shaDigest = MessageDigest.getInstance("SHA-256")

    fun randomBytes(number: Int): ByteArray {
        val byteArray = ByteArray(number)
        when {
//            Build.VERSION.SDK_INT >= Build.VERSION_CODES.O -> {
//                SecureRandom.getInstanceStrong().nextBytes(byteArray)
//            }
            else -> SecureRandom().nextBytes(byteArray)
        }
        return byteArray
    }


    /**
    Obtain the public elliptic curve SECP256K1 key from a private
     */
    fun getPublicKeyFromECPrivateKey(privateKey: ByteArray): ByteArray {
        val ecSpec: ECNamedCurveParameterSpec = ECNamedCurveTable.getParameterSpec(SECP256K1)
        val ecPrivateKey = ECPrivateKey(256, BigInteger(1, privateKey))
        val pointQ: ECPoint = ecSpec.g.multiply(ecPrivateKey.key)
        val useCompressedPointEncoding = false
        return pointQ.getEncoded(useCompressedPointEncoding)
    }

    /**
    ECDSA
     */
    fun sign(privateKeyData: ByteArray, message: ByteArray): ByteArray {
        if (privateKeyData.count() != 32) throw CryptoException.BadPrivateKeyException()
        if (message.count() <= 0) throw CryptoException.EmptyMessageException()
        if (message.count() > 32) throw CryptoException.MessageTooLongException()
        val keyFactory = KeyFactory.getInstance("EC")
        val ecParameterSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec(SECP256K1)
        val privateKeySpec = org.bouncycastle.jce.spec.ECPrivateKeySpec(
            BigInteger(1, privateKeyData),
            ecParameterSpec
        )
        val privateKey = keyFactory.generatePrivate(privateKeySpec)
        val signer = Signature.getInstance("SHA256withECDSA")
            .apply {
                initSign(privateKey)
                update(message)
            }
        return signer.sign()
    }

    /**
    Verify ECDSA signatures
     */
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        if (publicKey.count() != 65 || publicKey[0] != 4.toByte()) throw CryptoException.BadPublicKeyException()
        if (message.count() <= 0) throw CryptoException.EmptyMessageException()
        if (message.count() > 32) throw CryptoException.MessageTooLongException()
        val keyFactory = KeyFactory.getInstance("EC")
        val namedCurveSpec = ECNamedCurveSpec(SECP256K1, ecSpec.curve, ecSpec.g, ecSpec.n)
        val point: java.security.spec.ECPoint =
            ECPointUtil.decodePoint(namedCurveSpec.curve, publicKey)
        val pubKeySpec = java.security.spec.ECPublicKeySpec(point, namedCurveSpec)
        val key = keyFactory.generatePublic(pubKeySpec)
        val s = Signature.getInstance("SHA256withECDSA")
            .apply {
                initVerify(key)
                update(message)
            }
        return s.verify(signature)
    }

    /**
    Decrypt serialised AES-128-CTR
    Using ECDH shared secret KDF
     */
    fun decryptShared(sharedPx: ByteArray, encrypted: ByteArray): ByteArray {
        val sharedPrivateKey = kdf(sharedPx, 32)
        return decrypt(sharedPrivateKey, encrypted)
    }

    /**
    Decrypt serialised AES-128-CTR
     */
    private fun decrypt(privateKey: ByteArray, encrypted: ByteArray): ByteArray {
        val ephemeralPublicKeyLength = 1 + 64
        val ivLength = 16
        val metaLength = ephemeralPublicKeyLength + ivLength + 32
        if (encrypted.count() < metaLength || encrypted[0] < 2 || encrypted[0] > 4) throw CryptoException.InvalidCipherTextException()
        val ephemPublicKey = encrypted.sliceArray(0..64)
        val cipherTextLength = encrypted.count() - metaLength
        val iv = encrypted.sliceArray(65 until 65 + ivLength)
        val cipherAndIv = encrypted.sliceArray(65 until 65 + ivLength + cipherTextLength)
        val cipherText = cipherAndIv.sliceArray(ivLength..cipherAndIv.lastIndex)
        val msgMac = encrypted.sliceArray(65 + ivLength + cipherTextLength..encrypted.lastIndex)
        // check HMAC
        val px = derive(privateKey, ephemPublicKey)
        val hash = kdf(px, 32)
        val sha = MessageDigest.getInstance("SHA-256")
        sha.update(hash.sliceArray(16..hash.lastIndex))
        val macKey = sha.digest()
        if (!hmacSha256Sign(
                macKey,
                cipherAndIv
            ).contentEquals(msgMac)
        ) throw CryptoException.IncorrectMACException()

        val encryptionKeyArray = hash.sliceArray(0..15)
        val encryptionKey = SecretKeySpec(encryptionKeyArray, SECP256K1)
        return performAesCtr(iv, encryptionKey, cipherText, Cipher.DECRYPT_MODE)
    }

    /**
    Encrypt AES-128-CTR and serialise as in Parity
    Using ECDH shared secret KDF
    Serialization: <ephemPubKey><IV><CipherText><HMAC>
     */
    fun encryptShared(
        privateKeySender: ByteArray,
        publicKeyRecipient: ByteArray,
        msg: ByteArray,
        ephemPrivateKey: ByteArray? = null,
        iv: ByteArray? = null
    ): ByteArray {
        val sharedPx = derive(privateKeySender, publicKeyRecipient)
        return encryptShared(sharedPx, msg)
    }

    fun encryptShared(
        sharedPx: ByteArray,
        message: ByteArray,
        ephemPrivateKey: ByteArray? = null,
        iv: ByteArray? = null
    ): ByteArray {
        val sharedPrivateKey = kdf(sharedPx, 32)
        val sharedPublicKey = getPublicKeyFromECPrivateKey(sharedPrivateKey)
        return encrypt(sharedPublicKey, message)
    }

    /**
    Encrypt AES-128-CTR and serialise as in Parity
    Serialization: <ephemPubKey><IV><CipherText><HMAC>
     */
    fun encrypt(publicKeyTo: ByteArray, message: ByteArray): ByteArray {
        val ephemeralPrivateKey = randomBytes(32)
        val ephemeralPublicKey = getPublicKeyFromECPrivateKey(ephemeralPrivateKey)
        val iv = randomBytes(16)

        val sharedPx = derive(ephemeralPrivateKey, publicKeyTo)
        val hash = kdf(sharedPx, 32)
        val encryptionKeyArray = hash.sliceArray(0..15)
        val sha = MessageDigest.getInstance("SHA-256")
        sha.update(hash.sliceArray(16..hash.lastIndex))
        val macKey = sha.digest()
        val encryptionKey = SecretKeySpec(encryptionKeyArray, SECP256K1)
        val cipherText = performAesCtr(iv, encryptionKey, message, Cipher.ENCRYPT_MODE)
        val dataToMac = iv + cipherText
        val hmac = hmacSha256Sign(macKey, dataToMac)
        return ephemeralPublicKey + iv + cipherText + hmac
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
        return firstChunk?.let { it + secondChunk } ?: secondChunk
    }

    /**
    ECDH
     */
    fun derive(privateKeyA: ByteArray, publicKeyB: ByteArray): ByteArray {
        val keyA = BigInteger(1, privateKeyA)
        val curve = ecSpec.curve
        val keyB = curve.decodePoint(publicKeyB)
        val derivedPoint = curve.multiplier.multiply(keyB, keyA)
        return derivedPoint.getEncoded(useCompressedPointEncoding)
    }

    private fun kdf(secret: ByteArray, outputLength: Int): ByteArray {
        var ctr = 1
        var written = 0
        var result = ByteArray(0)
        while (written < outputLength) {
            val byteFunction = { index: Int ->
                when (index) {
                    0 -> ctr.ushr(24).toByte()
                    1 -> ctr.ushr(16).toByte()
                    2 -> ctr.ushr(8).toByte()
                    else -> ctr.toByte()
                }
            }
            val ctrs = ByteArray(4, byteFunction)
            shaDigest.update(ctrs + secret)
            val hashResult = shaDigest.digest()
            result += hashResult
            written += 32
            ctr += 1
        }
        return result
    }

    private fun hmacSha256Sign(key: ByteArray, message: ByteArray): ByteArray {
        val sha256HMAC = Mac.getInstance(HMACSHA256)
        val secretKey = SecretKeySpec(key, HMACSHA256)
        sha256HMAC.init(secretKey)
        return sha256HMAC.doFinal(message)
    }

}
