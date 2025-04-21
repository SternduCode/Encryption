package com.sterndu.encryption

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.*
import java.util.logging.Level
import javax.crypto.*
import javax.crypto.spec.*
import kotlin.math.pow

object CrypterProvider {

	private val availableCrypters: Map<Short, () -> Crypter> = HashMap<Short, () -> Crypter>().apply {
		val algorithms = Security.getAlgorithms("Cipher")

		if (algorithms.contains("AES/GCM/NOPADDING")) {
			this[1] = {
				object : Crypter("AES/GCM/NoPadding") {

					val MAX_ENCRYPTIONS = Int.MAX_VALUE.toUInt() // Actual maximum is 2^32 but to be safe we use 2^31-1 instead
					val MAX_DATA = 2.0.pow(35).toLong() // 32 GiB b/c 64 GiB is the maximum

					var encryptions = 0u
					var encryptedData = 0L

					val crypterThis = this

					override fun getKeySize() = 16

					override fun shouldGetANewKey() = encryptions >= MAX_ENCRYPTIONS || encryptedData >= MAX_DATA

					@Synchronized
					override fun decrypt(data: ByteArray): ByteArray {
						if (key != null) try {
							val byteBuffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
							val length = byteBuffer.getInt(0)
							val iv = ByteArray(length)
							byteBuffer[iv]
							val aesParams = GCMParameterSpec(128, iv)
							val newData = ByteArray(byteBuffer.remaining())
							byteBuffer[newData]
							cipher.init(Cipher.DECRYPT_MODE, key, aesParams)
							return cipher.doFinal(newData)
								.apply {
									synchronized(crypterThis) {
										encryptions++
										encryptedData += this.size
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
							cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
							val newData = cipher.doFinal(data)
							return ByteBuffer.allocate(4 + iv.size + newData.size)
								.order(ByteOrder.BIG_ENDIAN)
								.putInt(iv.size)
								.put(iv)
								.put(newData)
								.array()
								.apply {
									synchronized(crypterThis) {
										encryptions++
										encryptedData += data.size
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

					@Throws(InvalidKeyException::class)
					override fun makeKey(data: ByteArray) {
						if (data.size < getKeySize()) throw InvalidKeyException("The key material that was supplied has too few bytes")
						key = SecretKeySpec(data, 0, getKeySize(), "AES")
					}
				}
			}
		} else if (algorithms.contains("AES_128/GCM/NOPADDING")) {
			this[1] = {
				object : Crypter("AES_128/GCM/NoPadding") {

					val MAX_ENCRYPTIONS = Int.MAX_VALUE.toUInt() // Actual maximum is 2^32 but to be safe we use 2^31-1 instead
					val MAX_DATA = 2.0.pow(35).toLong() // 32 GiB b/c 64 GiB is the maximum

					var encryptions = 0u
					var encryptedData = 0L

					val crypterThis = this

					override fun getKeySize() = 16

					override fun shouldGetANewKey() = encryptions >= MAX_ENCRYPTIONS || encryptedData >= MAX_DATA

					@Synchronized
					override fun decrypt(data: ByteArray): ByteArray {
						if (key != null) try {
							val byteBuffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
							val length = byteBuffer.getInt(0)
							val iv = ByteArray(length)
							byteBuffer[iv]
							val aesParams = GCMParameterSpec(128, iv)
							val newData = ByteArray(byteBuffer.remaining())
							byteBuffer[newData]
							cipher.init(Cipher.DECRYPT_MODE, key, aesParams)
							return cipher.doFinal(newData)
								.apply {
									synchronized(crypterThis) {
										encryptions++
										encryptedData += this.size
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
							cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
							val newData = cipher.doFinal(data)
							return ByteBuffer.allocate(4 + iv.size + newData.size)
								.order(ByteOrder.BIG_ENDIAN)
								.putInt(iv.size)
								.put(iv)
								.put(newData)
								.array()
								.apply {
									synchronized(crypterThis) {
										encryptions++
										encryptedData += data.size
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

					@Throws(InvalidKeyException::class)
					override fun makeKey(data: ByteArray) {
						if (data.size < getKeySize()) throw InvalidKeyException("The key material that was supplied has too few bytes")
						key = SecretKeySpec(data, 0, getKeySize(), "AES")
					}
				}
			}
		}
		if (algorithms.contains("AES_256/GCM/NOPADDING")) {
			this[10] = {
				object : Crypter("AES_256/GCM/NoPadding") {

					val MAX_ENCRYPTIONS = Int.MAX_VALUE.toUInt() // Actual maximum is 2^32 but to be safe we use 2^31-1 instead
					val MAX_DATA = 2.0.pow(35).toLong() // 32 GiB b/c 64 GiB is the maximum

					var encryptions = 0u
					var encryptedData = 0L

					val crypterThis = this

					override fun getKeySize() = 32

					override fun shouldGetANewKey() = encryptions >= MAX_ENCRYPTIONS || encryptedData >= MAX_DATA

					@Synchronized
					override fun decrypt(data: ByteArray): ByteArray {
						if (key != null) try {
							val byteBuffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
							val length = byteBuffer.getInt()
							//println("IV Size: $length")
							val iv = ByteArray(length)
							byteBuffer[iv]
							//println("IV: ${iv.contentToString()}")
							val aesParams = GCMParameterSpec(128, iv)
							val newData = ByteArray(byteBuffer.remaining())
							byteBuffer[newData]
							//println("Data: ${newData.size}  ${newData.contentToString()}")
							cipher.init(Cipher.DECRYPT_MODE, key, aesParams)
							return cipher.doFinal(newData)
								.apply {
									synchronized(crypterThis) {
										encryptions++
										encryptedData += this.size
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
							cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, iv))
							val newData = cipher.doFinal(data)
							return ByteBuffer.allocate(4 + iv.size + newData.size)
								.order(ByteOrder.BIG_ENDIAN)
								.putInt(iv.size)
								.put(iv)
								.put(newData)
								.array()
								.apply {
									synchronized(crypterThis) {
										encryptions++
										encryptedData += data.size
									}
//									println("IV Size: " + iv.size)
//									println("IV: " + iv.contentToString())
//									println("Data: ${newData.size}  ${newData.contentToString()}")
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
						if (data.size < getKeySize()) throw InvalidKeyException("The key material that was supplied has too few bytes")
						key = SecretKeySpec(data, 0, getKeySize(), "AES")
					}
				}
			}
		}
		if (algorithms.contains("CHACHA20-POLY1305")) {
			this[20] = {
				object : Crypter("ChaCha20-Poly1305") {

					val MAX_ENCRYPTIONS = Int.MAX_VALUE.toUInt() // Actual maximum is 2^32 but to be safe we use 2^31-1 instead
					val MAX_DATA = 2.0.pow(37).toLong() // 128 GiB b/c 256 GiB is the maximum

					var encryptions = 0u
					var encryptedData = 0L

					val crypterThis = this

					override fun getKeySize() = 32

					override fun shouldGetANewKey() = encryptions >= MAX_ENCRYPTIONS || encryptedData >= MAX_DATA

					override fun decrypt(data: ByteArray): ByteArray {
						if (key != null) try {
							val byteBuffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
							val length = byteBuffer.getInt()
							val nonce = ByteArray(length)
							byteBuffer[nonce]
							val chaChaParams = IvParameterSpec(nonce)
							val newData = ByteArray(byteBuffer.remaining())
							byteBuffer[newData]
							cipher.init(Cipher.DECRYPT_MODE, key, chaChaParams)
							return cipher.doFinal(newData)
								.apply {
									synchronized(crypterThis) {
										encryptions++
										encryptedData += this.size
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

					override fun encrypt(data: ByteArray): ByteArray {
						if (key != null) try {
							val nonce = ByteArray(12)
							SecureRandom().nextBytes(nonce)
							cipher.init(Cipher.ENCRYPT_MODE, key, IvParameterSpec(nonce))
							val newData = cipher.doFinal(data)
							return ByteBuffer.allocate(4 + nonce.size + newData.size)
								.order(ByteOrder.BIG_ENDIAN)
								.putInt(nonce.size)
								.put(nonce)
								.put(newData)
								.array()
								.apply {
									synchronized(crypterThis) {
										encryptions++
										encryptedData += data.size
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

					@Throws(InvalidKeyException::class)
					override fun makeKey(data: ByteArray) {
						if (data.size < getKeySize()) throw InvalidKeyException("The key material that was supplied has too few bytes")
						key = SecretKeySpec(data, 0, getKeySize(), "ChaCha20")
					}
				}
			}
		}
	}

	val availableCryptersCodes: ShortArray = availableCrypters.keys.toShortArray()

	fun getCrypterByCode(code: Short): Crypter? {
		if (availableCryptersCodes.contains(code)) {
			return availableCrypters[code]?.let { it() }
		}
		return null
	}

}

fun main() {
	println(Security.getAlgorithms("Cipher"))

	for (provider in Security.getProviders()) {
		println(provider.name)
		for (key in provider.stringPropertyNames()) if (key.contains("Cipher")) println("\t" + key + "\t" + provider.getProperty(key))
	}

	println(Security.getAlgorithms("Cipher.Ch"))
}