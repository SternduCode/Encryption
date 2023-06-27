@file:JvmName("DiffieHellman")
package com.sterndu.encryption

import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyPairGenerator
import java.security.NoSuchAlgorithmException
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.KeyAgreement
import javax.crypto.interfaces.DHPublicKey

class DiffieHellman {
	private lateinit var secret: ByteArray
	private lateinit var ka: KeyAgreement
	private lateinit var kpg: KeyPairGenerator
	lateinit var publicKey: DHPublicKey
		private set

	// 0=No Handshake; 1=Doing Handshake; 2=Done Handshake;
	private var handshakeState = 0
	private fun newKey(vararg data: Any): DHPublicKey {
		return try {
			if (!doingHandshake) handshakeState = 1
			ka = KeyAgreement.getInstance("DiffieHellman")
			kpg = KeyPairGenerator.getInstance("DiffieHellman")
			if (System.getProperty("debug") == "true") println("A")
			kpg.initialize(2048)
			if (System.getProperty("debug") == "true") println("B")
			val keyPair = kpg.generateKeyPair()
			if (System.getProperty("debug") == "true") println("C")
			ka.init(keyPair.private)
			if (System.getProperty("debug") == "true") println("D")
			keyPair.public as DHPublicKey
		} catch (e: InvalidKeyException) {
			e.printStackTrace()
			if (data.isEmpty()) newKey(1) else newKey(data[0] as Int + 1)
		} catch (e: NoSuchAlgorithmException) {
			e.printStackTrace()
			if (data.isEmpty()) newKey(1) else newKey(data[0] as Int + 1)
		}
	}

	fun doPhase(key: DHPublicKey, lastPhase: Boolean) {
		try {
			ka.doPhase(key, lastPhase)
			if (lastPhase) {
				secret = ka.generateSecret()
				handshakeState = 2
			}
		} catch (e: InvalidKeyException) {
			e.printStackTrace()
		} catch (e: IllegalStateException) {
			e.printStackTrace()
		}
	}

	fun getSecret(): ByteArray? {
		return if (handshakeDone) secret else null
	}

	@Throws(InvalidAlgorithmParameterException::class)
	fun initialize(params: AlgorithmParameterSpec?) {
		if (doingHandshake) {
			kpg.initialize(params)
			try {
				val keyPair = kpg.generateKeyPair()
				ka.init(keyPair.private)
				publicKey = keyPair.public as DHPublicKey
			} catch (e: InvalidKeyException) {
				e.printStackTrace()
			}
		}
	}

	val doingHandshake: Boolean
		get() = handshakeState == 1
	val handshakeDone: Boolean
		get() = handshakeState == 2

	fun startHandshake() {
		if (!doingHandshake) {
			handshakeState = 1
			publicKey = newKey()
		}
	}
}
