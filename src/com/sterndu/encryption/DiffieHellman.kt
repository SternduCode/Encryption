@file:JvmName("DiffieHellman")
package com.sterndu.encryption

import com.sterndu.encryption.DiffieHellmanWithKyber.Companion.DIFFIE_HELLMAN_WITH_KYBER
import com.sterndu.encryption.KeyExchange.HandshakeState.*
import com.sterndu.multicore.LoggingUtil
import java.security.*
import java.security.spec.NamedParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.logging.Level.SEVERE
import java.util.logging.Level.WARNING
import java.util.logging.Logger
import javax.crypto.KDF
import javax.crypto.KeyAgreement
import javax.crypto.spec.HKDFParameterSpec

class DiffieHellman: KeyExchange() {

	override val id: Byte = 1

	private var logger: Logger = LoggingUtil.getLogger(DIFFIE_HELLMAN)
	private var sessionHash: MessageDigest = MessageDigest.getInstance("SHA-256")
	private var keyAgreement: KeyAgreement? = null

	var publicKey: PublicKey? = null
		private set

	/**
	 * Produces an output only if the handshake gets initialized during this function call
	 */
	fun doPhase(keyData: ByteArray, lastPhase: Boolean, aad: ByteArray = ByteArray(0)): ByteArray? {
		try {
            val sessionHash = sessionHash
			sessionHash.update(keyData)
			updateAdditionalAuthenticatedData(aad)
			val result = if (!doingHandshake) {
				startHandshake()
			} else {
				ByteArray(0)
			}
			val keyAgreement = keyAgreement

			if (keyAgreement == null) {
				logger.log(WARNING, DIFFIE_HELLMAN, Error(NOT_INITIALIZED_ERROR_MESSAGE))
				reset()
				return null
			}

			val kf = KeyFactory.getInstance("X25519")
			val key = kf.generatePublic(X509EncodedKeySpec(keyData))
			keyAgreement.doPhase(key, lastPhase)
			if (lastPhase) {
				handshakeState = DONE
			}
			return result
		} catch (e: InvalidKeyException) {
			logger.log(WARNING, DIFFIE_HELLMAN, e)
			reset()
		} catch (e: IllegalStateException) {
			logger.log(WARNING, DIFFIE_HELLMAN, e)
			reset()
		}
		return null
	}

	override fun doPhase(data: ByteArray, aad: ByteArray): ByteArray? {
		return doPhase(data, true, aad)
	}

	override fun getSecret(data: ByteArray): ByteArray? {
		return if (handshakeDone) {
			val sessionHash = sessionHash
			val secret = keyAgreement?.generateSecret()
			if (secret == null) {
				logger.log(WARNING, DIFFIE_HELLMAN_WITH_KYBER, Error(NOT_INITIALIZED_ERROR_MESSAGE))
				reset()
				return null
			}
			val kdf = KDF.getInstance("HKDF-SHA256")
			val spec = HKDFParameterSpec.ofExtract().addIKM(secret).addSalt(sessionHash.digest()).extractOnly()
			kdf.deriveData(spec)
		} else null
	}

	override fun startHandshake(): ByteArray? {
		if (!doingHandshake) {
			try {
				handshakeState = IN_PROGRESS
                val keyAgreement: KeyAgreement = KeyAgreement.getInstance("X25519")
				val keyPairGenerator: KeyPairGenerator = KeyPairGenerator.getInstance("XDH")
				if (System.getProperty("debug") == "true") println("A")
				keyPairGenerator.initialize(NamedParameterSpec("X25519"))
				if (System.getProperty("debug") == "true") println("B")
				val keyPair = keyPairGenerator.generateKeyPair()
				if (System.getProperty("debug") == "true") println("C")
				keyAgreement.init(keyPair.private)
				if (System.getProperty("debug") == "true") println("D")
				this.keyAgreement = keyAgreement
				publicKey = keyPair.public
				val pubKeyEnc = keyPair.public.encoded
				return allocateByteBuffer(pubKeyEnc.packingSize)
					.put(pubKeyEnc)
					.array()
					.also { sessionHash.update(it) }
			} catch (e: InvalidKeyException) {
				logger.log(SEVERE, DIFFIE_HELLMAN, e)
				reset()
			} catch (e: NoSuchAlgorithmException) {
				logger.log(SEVERE, DIFFIE_HELLMAN, e)
				reset()
			}
		}
		return null
	}

	override fun updateAdditionalAuthenticatedData(data: ByteArray) {
        sessionHash.update(data)
	}

	override fun reset() {
		handshakeState = UNINITIALIZED
		sessionHash.reset()
		keyAgreement = null
		publicKey = null
	}

	companion object {
		const val DIFFIE_HELLMAN = "Diffie Hellman"

		const val NOT_INITIALIZED_ERROR_MESSAGE = "Handshake wasn't started yet or rehandshake hasn't been properly started!"
	}
}
