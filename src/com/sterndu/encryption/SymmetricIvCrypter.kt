@file:JvmName("IVCrypter")
package com.sterndu.encryption

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.SecureRandom
import java.security.spec.AlgorithmParameterSpec
import java.util.logging.Level
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KDF
import javax.crypto.spec.HKDFParameterSpec
import javax.crypto.spec.SecretKeySpec

open class SymmetricIvCrypter(
    algorithm: String,
    val keyAlgorithm: String,
    maxEncryptions: UInt,
    maxData: ULong,
    keySize: Int,
    val parameterSpecFromIv: (ByteArray) -> AlgorithmParameterSpec
): Crypter(algorithm, maxEncryptions, maxData, keySize) {

    private var ivPrefix: ByteArray = ByteArray(0)

    @Synchronized
    override fun decrypt(data: ByteArray, aadData: Crypter.() -> ByteArray): ByteArray {
        if (keyDecryption != null) try {
            val byteBuffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
            val length = byteBuffer.getInt()
            if (length != 4) return ByteArray(0)
            val iv = ByteArray(12)
            byteBuffer[iv, 0, length]
            ByteBuffer.wrap(iv)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(4, decryptions.toInt())
            val params = parameterSpecFromIv(iv)
            val newData = ByteArray(byteBuffer.remaining())
            byteBuffer[newData]
            cipherDecryption.init(Cipher.DECRYPT_MODE, keyDecryption, params)
            cipherDecryption.updateAAD(aadData())
            cipherDecryption.updateAAD(iv)
            return cipherDecryption.doFinal(newData)
                .also {
                    decryptions++
                    encryptedData += it.size.toUInt()
                }
        } catch (e: InvalidKeyException) {
            logger.log(Level.WARNING, logger.name, e)
        } catch (e: IllegalBlockSizeException) {
            logger.log(Level.WARNING, logger.name, e)
        } catch (e: BadPaddingException) {
            logger.log(Level.WARNING, logger.name, e)
        } catch (e: InvalidAlgorithmParameterException) {
            logger.log(Level.WARNING, logger.name, e)
        }
        return ByteArray(0)
    }

    @Synchronized
    override fun encrypt(data: ByteArray, aadData: Crypter.() -> ByteArray): ByteArray {
        if (keyEncryption != null) try {
            val iv = ByteArray(12)
            ByteBuffer.wrap(iv)
                .order(ByteOrder.BIG_ENDIAN)
                .put(ivPrefix)
                .putInt(encryptions.toInt())
            cipherEncryption.init(Cipher.ENCRYPT_MODE, keyEncryption, parameterSpecFromIv(iv))
            cipherEncryption.updateAAD(aadData())
            cipherEncryption.updateAAD(iv)
            val newData = cipherEncryption.doFinal(data)
            return allocateByteBuffer(ivPrefix.packingSizeWithLength + newData.packingSize)
                .putByteArrayWithLength(ivPrefix)
                .put(newData)
                .array()
                .also {
                    encryptions++
                    encryptedData += data.size.toUInt()
                }
        } catch (e: InvalidKeyException) {
            logger.log(Level.WARNING, logger.name, e)
        } catch (e: IllegalBlockSizeException) {
            logger.log(Level.WARNING, logger.name, e)
        } catch (e: BadPaddingException) {
            logger.log(Level.WARNING, logger.name, e)
        } catch (e: InvalidAlgorithmParameterException) {
            logger.log(Level.WARNING, logger.name, e)
        }
        return ByteArray(0)
    }

    @Throws(InvalidKeyException::class)
    override fun makeKeys(masterSecret: ByteArray, host: Boolean) {
        val masterSecretKey = SecretKeySpec(masterSecret, "Generic")
        val hostInfo = "Host".toByteArray()
        val clientInfo = "Client".toByteArray()
        val kdf = KDF.getInstance("HKDF-SHA256")
        val specEncryption = HKDFParameterSpec.expandOnly(masterSecretKey, if (host) hostInfo else clientInfo, keySize)
        val specDecryption = HKDFParameterSpec.expandOnly(masterSecretKey, if (host) clientInfo else hostInfo, keySize)

        keyEncryption = kdf.deriveKey(keyAlgorithm, specEncryption)
        keyDecryption = kdf.deriveKey(keyAlgorithm, specDecryption)
        ivPrefix = ByteArray(4).also {
            SecureRandom().nextBytes(it)
        }
        encryptions = 0u
        decryptions = 0u
        encryptedData = 0u
        decryptedData = 0u
    }

    override fun getOutputPacketSize(inputSize: Int): Int {
        if (ivPrefix.isEmpty()) error("Crypter not initialized")
        return ivPrefix.packingSizeWithLength + cipherEncryption.getOutputSize(inputSize)
    }

}