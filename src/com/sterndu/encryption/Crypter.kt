@file:JvmName("Crypter")
package com.sterndu.encryption

import java.security.InvalidKeyException
import java.security.Key
import javax.crypto.Cipher

abstract class Crypter protected constructor(private val algorithm: String) {
	var cipher: Cipher
		protected set

	var key: Key? = null
		protected set

	var secondaryKey: Key? = null
		protected set

	abstract fun getKeySize(): Int

	init {
		cipher = Cipher.getInstance(algorithm)
	}

	fun getAlgorithm() : String = algorithm

	abstract fun shouldGetANewKey(): Boolean

	abstract fun decrypt(data: ByteArray): ByteArray

	abstract fun encrypt(data: ByteArray): ByteArray

	@Throws(InvalidKeyException::class)
	abstract fun makeKey(data: ByteArray)

	@Throws(InvalidKeyException::class)
	open fun makeSecondaryKey(data: ByteArray) {}   // default implementation. As many algorithms (i.e. symmetric algorithms) don't need two keys,
													// we leave it empty but still provide it
}
