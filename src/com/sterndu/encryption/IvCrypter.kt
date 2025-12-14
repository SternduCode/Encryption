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

open class IvCrypter(algorithm: String, val keyAlgorithm: String, MAX_ENCRYPTIONS: UInt, MAX_DATA: Long, keySize: Int, val parameterSpecFromIv: (ByteArray) -> AlgorithmParameterSpec):
    Crypter(algorithm, MAX_ENCRYPTIONS, MAX_DATA, keySize) {

    @Synchronized
    override fun decrypt(data: ByteArray): ByteArray {
        if (key != null) try {
            val byteBuffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
            val length = byteBuffer.getInt()
            //println("IV Size: $length")
            val iv = ByteArray(length)
            byteBuffer[iv]
            //println("IV: ${iv.contentToString()}")
            val params = parameterSpecFromIv(iv)
            val newData = ByteArray(byteBuffer.remaining())
            byteBuffer[newData]
            //println("Data: ${newData.size}  ${newData.contentToString()}")
            cipher.init(Cipher.DECRYPT_MODE, key, params)
            return cipher.doFinal(newData)
                .also {
                    synchronized(this) {
                        encryptions++
                        encryptedData += it.size
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
    override fun encrypt(data: ByteArray): ByteArray {
        if (key != null) try {
            val iv = ByteArray(12)
            SecureRandom().nextBytes(iv)
            cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpecFromIv(iv))
            val newData = cipher.doFinal(data)
            return ByteBuffer.allocate(4 + iv.size + newData.size)
                .order(ByteOrder.BIG_ENDIAN)
                .putInt(iv.size)
                .put(iv)
                .put(newData)
                .array()
                .also {
                    synchronized(this) {
                        encryptions++
                        encryptedData += data.size
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
    }

}