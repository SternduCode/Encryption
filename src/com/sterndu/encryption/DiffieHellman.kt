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
	private lateinit var publicKey: DHPublicKey

	// 0=No Handshake; 1=Doing Handshake; 2=Done Handshake;
	private var handshakeState = 0
	private fun newKey(vararg data: Any): DHPublicKey {
		return try {
			if (handshakeState != 1) handshakeState = 1
			ka = KeyAgreement.getInstance("DiffieHellman")
			kpg = KeyPairGenerator.getInstance("DiffieHellman")
			kpg.initialize(2048)
			val keyPair = kpg.generateKeyPair()
			ka.init(keyPair.private)
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
		return if (handshakeState == 2) secret else null
	}

	fun getPublicKey(): DHPublicKey {
		return publicKey
	}

	@Throws(InvalidAlgorithmParameterException::class)
	fun initialize(params: AlgorithmParameterSpec?) {
		if (handshakeState == 1) {
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

	val isDoingHandshake: Boolean
		get() = handshakeState == 1
	val isHandshakeDone: Boolean
		get() = handshakeState == 2

	fun startHandshake() {
		if (handshakeState != 1) {
			handshakeState = 1
			publicKey = newKey()
		}
	}
}
