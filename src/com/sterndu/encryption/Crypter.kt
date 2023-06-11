@file:JvmName("Crypter")
package com.sterndu.encryption

import java.security.InvalidKeyException
import java.security.Key
import javax.crypto.Cipher

/**
 * The Class Crypter.
 */
abstract class Crypter protected constructor(private val algorithm: String) {
	var cipher: Cipher
		protected set

	var key: Key? = null
		protected set

	var secondaryKey: Key? = null
		protected set

	/**
	 * Instantiates a new crypter.
	 */
	init {
		cipher = Cipher.getInstance(algorithm)
	}

	fun getAlgorithm() : String = algorithm

	/**
	 * Decrypt.
	 *
	 * @param data the data
	 * @return the byte[]
	 */
	abstract fun decrypt(data: ByteArray): ByteArray

	/**
	 * Encrypt.
	 *
	 * @param data the data
	 * @return the byte[]
	 */
	abstract fun encrypt(data: ByteArray): ByteArray

	/**
	 * Make key.
	 *
	 * @param data the data
	 * @throws InvalidKeyException the invalid key exception
	 */
	@Throws(InvalidKeyException::class)
	abstract fun makeKey(data: ByteArray)

	/**
	 * Make secondary key.
	 *
	 * @param data the data
	 */
	abstract fun makeSecondaryKey(data: ByteArray)
}
