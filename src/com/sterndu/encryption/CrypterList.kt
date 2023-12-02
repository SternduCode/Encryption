@file:JvmName("CrypterList")
package com.sterndu.encryption

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.*
import java.util.*
import java.util.function.Supplier
import javax.crypto.*
import javax.crypto.spec.*

/**
 * The Class CrypterList.
 */
object CrypterList {
	/** The versions.  */
	@JvmStatic
	private val versions: MutableMap<Int, Supplier<Crypter>> = HashMap()

	@JvmStatic
	fun getByVersion(version: Int): Crypter? = if (versions.contains(version)) versions[version]?.get() else null

	@JvmStatic
	val supportedVersions: IntArray
		get() = versions.keys.parallelStream().mapToInt { i: Int -> i }.toArray()

	init {
		try {
			Cipher.getInstance("AES/GCM/NoPadding")
			versions[1] = Supplier<Crypter> {
				object : Crypter("AES/GCM/NoPadding") {
					override fun decrypt(data: ByteArray): ByteArray {
						if (key != null) try {
							val length = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).getInt(0)
							val iv = data.copyOfRange(4, length + 4)
							val aesParams = GCMParameterSpec(128, iv)
							val newData = data.copyOfRange(4 + length, data.size)
							// println(newData.size + " " + Arrays.toString(newData));
							cipher.init(Cipher.DECRYPT_MODE, key, aesParams)
							return cipher.doFinal(newData)
						} catch (e: InvalidKeyException) {
							e.printStackTrace()
						} catch (e: IllegalBlockSizeException) {
							e.printStackTrace()
						} catch (e: BadPaddingException) {
							e.printStackTrace()
						} catch (e: InvalidAlgorithmParameterException) {
							e.printStackTrace()
						}
						return ByteArray(0)
					}

					override fun encrypt(data: ByteArray): ByteArray {
						if (key != null) try {
							val iv = ByteArray(12)
							SecureRandom().nextBytes(iv)
							cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
							val newData = cipher.doFinal(data)
							// println(newData.size + " " + Arrays.toString(newData));
							return ByteBuffer.allocate(4 + iv.size + newData.size)
								.order(ByteOrder.BIG_ENDIAN)
								.putInt(iv.size)
								.put(iv)
								.put(newData)
								.array()
						} catch (e: InvalidKeyException) {
							e.printStackTrace()
						} catch (e: IllegalBlockSizeException) {
							e.printStackTrace()
						} catch (e: BadPaddingException) {
							e.printStackTrace()
						} catch (e: InvalidAlgorithmParameterException) {
							e.printStackTrace()
						}
						return ByteArray(0)
					}

					@Throws(InvalidKeyException::class)
					override fun makeKey(data: ByteArray) {
						if (data.size < 16) throw InvalidKeyException("The key material that was supplied was of wrong length")
						key = SecretKeySpec(data, 0, when { data.size >= 32 -> 32; data.size >= 24 -> 24; else -> 16 }, "AES")
					}

					override fun makeSecondaryKey(data: ByteArray) {} //In AES we don't need two Keys
				}
			}
		} catch (_: Exception) {
			println("AES not available")
		}
		try {
			Cipher.getInstance("ChaCha20-Poly1305")
			versions[20] = Supplier<Crypter> {
				object : Crypter("ChaCha20-Poly1305") {
					override fun decrypt(data: ByteArray): ByteArray {
						if (key != null) try {
							val length = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).getInt(0)
							val nonce = data.copyOfRange(4, length + 4)
							val params = IvParameterSpec(nonce)
							val newData = data.copyOfRange(4 + length, data.size)
							// println(newData.size + " " + Arrays.toString(newData));
							cipher.init(Cipher.DECRYPT_MODE, key, params)
							return cipher.doFinal(newData)
						} catch (e: InvalidKeyException) {
							e.printStackTrace()
						} catch (e: IllegalBlockSizeException) {
							e.printStackTrace()
						} catch (e: BadPaddingException) {
							e.printStackTrace()
						} catch (e: InvalidAlgorithmParameterException) {
							e.printStackTrace()
						}
						return ByteArray(0)
					}

					override fun encrypt(data: ByteArray): ByteArray {
						if (key != null) try {
							val nonce = ByteArray(12)
							SecureRandom().nextBytes(nonce)
							cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(nonce))
							val newData = cipher.doFinal(data)
							// println(data.length + " " + Arrays.toString(data));
							return ByteBuffer.allocate(4 + nonce.size + newData.size)
								.order(ByteOrder.BIG_ENDIAN)
								.putInt(nonce.size)
								.put(nonce)
								.put(newData)
								.array()
						} catch (e: InvalidKeyException) {
							e.printStackTrace()
						} catch (e: IllegalBlockSizeException) {
							e.printStackTrace()
						} catch (e: BadPaddingException) {
							e.printStackTrace()
						} catch (e: InvalidAlgorithmParameterException) {
							e.printStackTrace()
						}
						return ByteArray(0)
					}

					@Throws(InvalidKeyException::class)
					override fun makeKey(data: ByteArray) {
						if (data.size < 32) throw InvalidKeyException("The key material that was supplied was of wrong length")
						key = SecretKeySpec(data, 0, 32, "ChaCha20")
					}

					override fun makeSecondaryKey(data: ByteArray) {} //In ChaCha20 we don't need two Keys
				}
			}
		} catch (_: Exception) {
			println("ChaCha20 not available")
		}
	}
}
