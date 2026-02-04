package com.sterndu.encryption

import com.sterndu.encryption.DiffieHellman.HandshakeState.*
import com.sterndu.multicore.LoggingUtil
import java.security.*
import java.security.spec.NamedParameterSpec
import java.util.logging.Level
import java.util.logging.Logger
import javax.crypto.KDF
import javax.crypto.KEM
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.HKDFParameterSpec

enum class KyberSecurityPerformanceBalance(val parameterSpecName: String, val cipertextSize: Int) {
    Performance("ML-KEM-512", 768), Balanced("ML-KEM-768", 1088), Security("ML-KEM-1024", 1568)
}

class DiffieHellmanWithKyber(val kyberSecurityPerformanceBalance: KyberSecurityPerformanceBalance) {

    enum class HandshakeState {
        UNINITIALIZED,
        IN_PROGRESS,
        DONE;
    }

    private var logger: Logger = LoggingUtil.getLogger(DIFFIE_HELLMAN_WITH_KYBER)
    private var secretDH = ByteArray(0)
    private var secretKyber: SecretKey? = null
    private var keyAgreementDH: KeyAgreement? = null
    var publicKeyDH: PublicKey? = null
        private set
    var publicKeyKyber: PublicKey? = null
        private set
    private var privateKeyKyber: PrivateKey? = null

    fun requiredEncapsulationSize(): Int = kyberSecurityPerformanceBalance.cipertextSize

    // 0=No Handshake; 1=Doing Handshake; 2=Done Handshake;
    private var handshakeState = UNINITIALIZED
    private fun newKey(vararg data: Any) {
        return try {
            if (!doingHandshake) handshakeState = IN_PROGRESS
            val keyAgreementDH: KeyAgreement = KeyAgreement.getInstance("X25519")
            val keyPairGeneratorDH: KeyPairGenerator = KeyPairGenerator.getInstance("XDH")
            val keyPairGeneratorKyber: KeyPairGenerator = KeyPairGenerator.getInstance("ML-KEM")
            if (System.getProperty("debug") == "true") println("A")
            keyPairGeneratorDH.initialize(NamedParameterSpec("X25519"))
            keyPairGeneratorKyber.initialize(NamedParameterSpec(kyberSecurityPerformanceBalance.parameterSpecName))
            if (System.getProperty("debug") == "true") println("B")
            val keyPairDH = keyPairGeneratorDH.generateKeyPair()
            val keyPairKyber = keyPairGeneratorKyber.generateKeyPair()
            if (System.getProperty("debug") == "true") println("C")
            keyAgreementDH.init(keyPairDH.private)
            if (System.getProperty("debug") == "true") println("D")
            this.keyAgreementDH = keyAgreementDH
            publicKeyDH = keyPairDH.public
            publicKeyKyber = keyPairKyber.public
            privateKeyKyber = keyPairKyber.private
        } catch (e: InvalidKeyException) {
            logger.log(Level.WARNING, DIFFIE_HELLMAN_WITH_KYBER, e)
            if (data.isEmpty()) newKey(1) else newKey(data[0] as Int + 1)
        } catch (e: NoSuchAlgorithmException) {
            logger.log(Level.WARNING, DIFFIE_HELLMAN_WITH_KYBER, e)
            if (data.isEmpty()) newKey(1) else newKey(data[0] as Int + 1)
        }
    }

    fun doPhase(keyDH: PublicKey, keyKyber: PublicKey?, encapsulationKyber: ByteArray, lastPhase: Boolean) {
        val keyAgreement = keyAgreementDH
        if (keyAgreement == null) {
            logger.log(Level.WARNING, DIFFIE_HELLMAN_WITH_KYBER, Error("Handshake wasn't started yet or rehandshake hasn't been properly started!"))
            return
        }
        try {
            keyAgreement.doPhase(keyDH, lastPhase)

            if (keyKyber != null) {
                val kemKyber = KEM.getInstance("ML-KEM")
                val encapsulatorKyber = kemKyber.newEncapsulator(keyKyber)
                val encapsulatedKyber = encapsulatorKyber.encapsulate()
                encapsulatedKyber.encapsulation().copyInto(encapsulationKyber)
                publicKeyKyber = null
                privateKeyKyber = null
                secretKyber = encapsulatedKyber.key()
            }

            if (lastPhase) {
                secretDH = keyAgreement.generateSecret()

                if (secretKyber == null) {
                    val kemKyber = KEM.getInstance("ML-KEM")
                    val decapsulatorKyber = kemKyber.newDecapsulator(privateKeyKyber)
                    publicKeyKyber = null
                    privateKeyKyber = null
                    secretKyber = decapsulatorKyber.decapsulate(encapsulationKyber)
                }
                publicKeyDH = null
                handshakeState = DONE
            }
        } catch (e: InvalidKeyException) {
            logger.log(Level.WARNING, DIFFIE_HELLMAN_WITH_KYBER, e)
        } catch (e: IllegalStateException) {
            logger.log(Level.WARNING, DIFFIE_HELLMAN_WITH_KYBER, e)
        }
    }

    fun getSecret(secretSize: Int): ByteArray? {
        return if (handshakeDone) {
            val kdf = KDF.getInstance("HKDF-SHA256")
            val spec = HKDFParameterSpec.ofExtract().addIKM(secretDH).addIKM(secretKyber).thenExpand(null, secretSize)
            kdf.deriveData(spec)
        } else null
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
        const val DIFFIE_HELLMAN_WITH_KYBER = "Diffie Hellman Kyber"
    }

}