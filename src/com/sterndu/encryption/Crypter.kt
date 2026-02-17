@file:JvmName("Crypter")
package com.sterndu.encryption

import com.sterndu.multicore.LoggingUtil
import java.security.InvalidKeyException
import java.security.Key
import javax.crypto.Cipher

abstract class Crypter protected constructor(val algorithm: String, val maxEncryptions: UInt, val maxData: ULong, val keySize: Int) {

	protected val logger = LoggingUtil.getLogger("Crypter $algorithm")

	val cipherEncryption: Cipher = Cipher.getInstance(algorithm)
    val cipherDecryption: Cipher = Cipher.getInstance(algorithm)

    var keyEncryption: Key? = null
		protected set
	var keyDecryption: Key? = null
		protected set

	var encryptions = 0u
		protected set

	var decryptions = 0u
		protected set

	var encryptedData = 0UL
		protected set

	var decryptedData = 0UL
		protected set

    open fun shouldGetANewKey(): Boolean = encryptions >= maxEncryptions || decryptions >= maxEncryptions || encryptedData >= maxData || decryptedData >= maxData

	abstract fun decrypt(data: ByteArray, aadData: Crypter.() -> ByteArray): ByteArray

	abstract fun encrypt(data: ByteArray, aadData: Crypter.() -> ByteArray): ByteArray

	@Throws(InvalidKeyException::class)
	abstract fun makeKeys(masterSecret: ByteArray, host: Boolean)

	/**
	 * Should return the exact size of the byte array returned by encrypt() for an input of the given size.
	 */
	abstract fun getOutputPacketSize(inputSize: Int): Int
}
