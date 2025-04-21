@file:JvmName("DiffieHellman")
package com.sterndu.encryption

import com.sterndu.encryption.DiffieHellman.HandshakeState.*
import com.sterndu.multicore.LoggingUtil
import java.security.*
import java.security.spec.NamedParameterSpec
import java.util.logging.Level
import java.util.logging.Logger
import javax.crypto.KeyAgreement

class DiffieHellman {

	enum class HandshakeState {
		UNINITIALIZED,
		IN_PROGRESS,
		DONE;
	}

	private var logger: Logger = LoggingUtil.getLogger(DIFFIE_HELLMAN)
	private var secret = ByteArray(0)
	private var keyAgreement: KeyAgreement? = null
	private var keyPairGenerator: KeyPairGenerator? = null
	var publicKey: PublicKey? = null
		private set

	// 0=No Handshake; 1=Doing Handshake; 2=Done Handshake;
	private var handshakeState = UNINITIALIZED
	private fun newKey(vararg data: Any) {
		return try {
			if (!doingHandshake) handshakeState = IN_PROGRESS
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
			this.keyPairGenerator = keyPairGenerator
			publicKey = keyPair.public
		} catch (e: InvalidKeyException) {
			logger.log(Level.WARNING, DIFFIE_HELLMAN, e)
			if (data.isEmpty()) newKey(1) else newKey(data[0] as Int + 1)
		} catch (e: NoSuchAlgorithmException) {
			logger.log(Level.WARNING, DIFFIE_HELLMAN, e)
			if (data.isEmpty()) newKey(1) else newKey(data[0] as Int + 1)
		}
	}

	fun doPhase(key: PublicKey, lastPhase: Boolean) {
		val keyAgreement = keyAgreement
		if (keyAgreement == null) {
			logger.log(Level.WARNING, DIFFIE_HELLMAN, Error("Handshake wasn't started yet or rehandshake hasn't been properly started!"))
			return
		}
		try {
			keyAgreement.doPhase(key, lastPhase)
			if (lastPhase) {
				secret = keyAgreement.generateSecret()
				handshakeState = DONE
			}
		} catch (e: InvalidKeyException) {
			logger.log(Level.WARNING, DIFFIE_HELLMAN, e)
		} catch (e: IllegalStateException) {
			logger.log(Level.WARNING, DIFFIE_HELLMAN, e)
		}
	}

	fun getSecret(): ByteArray? {
		return if (handshakeDone) secret else null
	}

	val doingHandshake: Boolean
		get() = handshakeState == IN_PROGRESS
	val handshakeDone: Boolean
		get() = handshakeState == DONE

	fun startHandshake() {
		if (!doingHandshake) {
			newKey()
		}
	}

	companion object {
		const val DIFFIE_HELLMAN = "Diffie Hellman"
	}
}
