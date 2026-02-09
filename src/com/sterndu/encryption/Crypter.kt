@file:JvmName("Crypter")
package com.sterndu.encryption

import com.sterndu.multicore.LoggingUtil
import java.security.InvalidKeyException
import java.security.Key
import javax.crypto.Cipher

abstract class Crypter protected constructor(val algorithm: String, val maxEncryptions: UInt, val maxData: ULong, val keySize: Int) {

	protected val logger = LoggingUtil.getLogger("Crypter $algorithm")

	var cipher: Cipher
		protected set

	var key: Key? = null
		protected set

	var secondaryKey: Key? = null
		protected set

	var encryptions = 0u
		protected set

	var encryptedData = 0UL
		protected set

	open fun getSecondKeySize(): Int = 0

	init {
		cipher = Cipher.getInstance(algorithm)
	}

	open fun shouldGetANewKey(): Boolean = encryptions >= maxEncryptions || encryptedData >= maxData

	abstract fun decrypt(data: ByteArray, aadData: Crypter.() -> ByteArray): ByteArray

	abstract fun encrypt(data: ByteArray, aadData: Crypter.() -> ByteArray): ByteArray

	@Throws(InvalidKeyException::class)
	abstract fun makeKey(data: ByteArray)

	@Throws(InvalidKeyException::class)
	open fun makeSecondaryKey(data: ByteArray) {}   // default implementation. As many algorithms (i.e. symmetric algorithms) don't need two keys,
													// we leave it empty but still provide it, as it might be useful for hybrid encryption algorithms.
}
