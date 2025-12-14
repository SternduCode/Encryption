package com.sterndu.encryption

import java.security.Security
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import kotlin.math.pow

object CrypterProvider {

	private val availableCrypters: Map<Short, () -> Crypter> = HashMap<Short, () -> Crypter>().also {
		val algorithms = Security.getAlgorithms("Cipher")

		if (algorithms.contains("AES/GCM/NOPADDING")) {
			it[1] = {
				IvCrypter(
					"AES/GCM/NoPadding",
					"AES",
					Int.MAX_VALUE.toUInt(), // Actual maximum is 2^32 but to be safe we use 2^31-1 instead
					2.0.pow(35).toLong(), // 32 GiB b/c 64 GiB is the maximum
					16,
					{ iv ->
						GCMParameterSpec(128, iv)
					},
				)
			}
		} else if (algorithms.contains("AES_128/GCM/NOPADDING")) {
			it[1] = {
				IvCrypter(
					"AES_128/GCM/NoPadding",
					"AES",
					Int.MAX_VALUE.toUInt(), // Actual maximum is 2^32 but to be safe we use 2^31-1 instead
					2.0.pow(35).toLong(), // 32 GiB b/c 64 GiB is the maximum
					16,
					{ iv ->
						GCMParameterSpec(128, iv)
					},
				)
			}
		}
		if (algorithms.contains("AES_256/GCM/NOPADDING")) {
			it[10] = {
				IvCrypter(
					"AES_256/GCM/NoPadding",
					"",
					Int.MAX_VALUE.toUInt(), // Actual maximum is 2^32 but to be safe we use 2^31-1 instead
					2.0.pow(35).toLong(), // 32 GiB b/c 64 GiB is the maximum
					32,
					{ iv ->
						GCMParameterSpec(128, iv)
					},
				)
			}
		}
		if (algorithms.contains("CHACHA20-POLY1305")) {
			it[20] = {
				IvCrypter(
					"ChaCha20-Poly1305",
					"ChaCha20",
					Int.MAX_VALUE.toUInt(), // Actual maximum is 2^32 but to be safe we use 2^31-1 instead
					2.0.pow(37).toLong(), // 128 GiB b/c 256 GiB is the maximum
					32,
					{ nonce ->
						IvParameterSpec(nonce)
					},
				)
			}
		}
	}

	val availableCrypterCodes: ShortArray = availableCrypters.keys.toShortArray()

	fun getCrypterByCode(code: Short): Crypter? {
		if (availableCrypterCodes.contains(code)) {
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