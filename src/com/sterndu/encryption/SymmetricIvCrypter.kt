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
        if (key != null) try {
            val byteBuffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
            val length = byteBuffer.getInt()
            //println("IV Size: $length")
            if (length != 4) return ByteArray(0)
            val iv = ByteArray(12)
            byteBuffer[iv, 0, length]
            ByteBuffer.wrap(iv)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(4, decryptions.toInt())
            //println("IV: ${iv.contentToString()}")
            val params = parameterSpecFromIv(iv)
            val newData = ByteArray(byteBuffer.remaining())
            byteBuffer[newData]
            //println("Data: ${newData.size}  ${newData.contentToString()}")
            cipher.init(Cipher.DECRYPT_MODE, key, params)
            cipher.updateAAD(aadData())
            cipher.updateAAD(iv)
            return cipher.doFinal(newData)
                .also {
                    synchronized(this) {
                        decryptions++
                        encryptedData += it.size.toUInt()
                    }
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
        if (key != null) try {
            val iv = ByteArray(12)
            ByteBuffer.wrap(iv)
                .order(ByteOrder.BIG_ENDIAN)
                .put(ivPrefix)
                .putInt(encryptions.toInt())
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpecFromIv(iv))
            cipher.updateAAD(aadData())
            cipher.updateAAD(iv)
            val newData = cipher.doFinal(data)
            return allocateByteBuffer(ivPrefix.packingSizeWithLength + newData.packingSize)
                .putByteArrayWithLength(ivPrefix)
                .put(newData)
                .array()
                .also {
                    synchronized(this) {
                        encryptions++
                        encryptedData += data.size.toUInt()
                    }
//					println("IV Size: " + iv.size)
//					println("IV: " + iv.contentToString())
//					println("Data: ${newData.size}  ${newData.contentToString()}")
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
    override fun makeKey(data: ByteArray) {
        if (data.size < keySize) throw InvalidKeyException("The key material that was supplied has too few bytes")
        key = SecretKeySpec(data, 0, keySize, keyAlgorithm)
        ivPrefix = ByteArray(4).also {
            SecureRandom().nextBytes(it)
        }
        encryptions = 0u
        decryptions = 0u
        encryptedData = 0u
    }

}