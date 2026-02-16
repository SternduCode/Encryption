package com.sterndu.encryption

import com.sterndu.encryption.KeyExchange.HandshakeState.*
import com.sterndu.multicore.LoggingUtil
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.*
import java.security.spec.NamedParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.util.logging.Level.WARNING
import java.util.logging.Logger
import javax.crypto.KDF
import javax.crypto.KEM
import javax.crypto.KeyAgreement
import javax.crypto.SecretKey
import javax.crypto.spec.HKDFParameterSpec

enum class KyberSecurityPerformanceBalance(val id: Int, val parameterSpecName: String, val ciphertextSize: Int) {
    Performance(0, "ML-KEM-512", 768), Balanced(1, "ML-KEM-768", 1088), Security(2, "ML-KEM-1024", 1568)
}

class DiffieHellmanWithKyber(val kyberSecurityPerformanceBalance: KyberSecurityPerformanceBalance): KeyExchange() {

    override val ID: Byte = 2

    private var logger: Logger = LoggingUtil.getLogger(DIFFIE_HELLMAN_WITH_KYBER)
    private var remoteSecretKyber: SecretKey? = null
    private var localSecretKyber: SecretKey? = null
    private var keyAgreementDH: KeyAgreement? = null
    private var decapsulatorKyber: KEM.Decapsulator? = null
    private var sessionHash: MessageDigest? = null
    var publicKeyDH: PublicKey? = null
        private set
    var publicKeyKyber: PublicKey? = null
        private set

    override fun doPhase(data: ByteArray): ByteArray? {
        val keyAgreement = keyAgreementDH
        val sessionHash = sessionHash
        val result = if (!doingHandshake) {
            startHandshake()
        } else {
            ByteArray(0)
        }
        if (keyAgreement == null || result == null || sessionHash == null) {
            logger.log(WARNING, DIFFIE_HELLMAN_WITH_KYBER, Error("Handshake wasn't started yet or rehandshake hasn't been properly started!"))
            reset()
            return null
        }
        try {
            sessionHash.update(data)

            val bb = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)

            val dhKeyData = bb.getByteArrayWithLength()
            val kyberKeyData = bb.getByteArrayWithLength()

            val kyberCiphertext = if (bb.remaining() > 0) bb.getByteArrayWithLength() else null

            val kfDH = KeyFactory.getInstance("X25519")
            val keyDH = kfDH.generatePublic(X509EncodedKeySpec(dhKeyData))
            keyAgreement.doPhase(keyDH, true)

            val kfKyber = KeyFactory.getInstance("ML-KEM")
            val keyKyber = kfKyber.generatePublic(X509EncodedKeySpec(kyberKeyData))

            val kemKyber = KEM.getInstance("ML-KEM")
            val encapsulatorKyber = kemKyber.newEncapsulator(keyKyber)
            val encapsulatedKyber = encapsulatorKyber.encapsulate()
            remoteSecretKyber = encapsulatedKyber.key()
            val encapsulationBytes = encapsulatedKyber.encapsulation()

            if (kyberCiphertext != null) {
                val decapsulatorKyber = decapsulatorKyber
                if (decapsulatorKyber == null) {
                    logger.log(WARNING, DIFFIE_HELLMAN_WITH_KYBER, Error("Handshake wasn't started yet or rehandshake hasn't been properly started!"))
                    reset()
                    return null
                }
                localSecretKyber = decapsulatorKyber.decapsulate(kyberCiphertext)
                handshakeState = DONE
            }

            return allocateByteBuffer(result.packingSize + encapsulationBytes.packingSizeWithLength)
                .put(result)
                .putByteArrayWithLength(encapsulationBytes)
                .array()
                .also { sessionHash.update(it) }
        } catch (e: InvalidKeyException) {
            logger.log(WARNING, DIFFIE_HELLMAN_WITH_KYBER, e)
            reset()
        } catch (e: IllegalStateException) {
            logger.log(WARNING, DIFFIE_HELLMAN_WITH_KYBER, e)
            reset()
        }
        return null
    }

    override fun getSecret(data: ByteArray): ByteArray? {
        return if (doingHandshake) {
            val sessionHash = sessionHash
            val dhSecret = keyAgreementDH?.generateSecret()
            val decapsulatorKyber = decapsulatorKyber
            if (sessionHash == null || dhSecret == null || decapsulatorKyber == null) {
                logger.log(WARNING, DIFFIE_HELLMAN_WITH_KYBER, Error("Handshake wasn't started yet or rehandshake hasn't been properly started!"))
                reset()
                return null
            }
            val bb = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)
            localSecretKyber = decapsulatorKyber.decapsulate(bb.getByteArrayWithLength())
            handshakeState = DONE
            sessionHash.update(data)
            val kdf = KDF.getInstance("HKDF-SHA256")
            val spec = HKDFParameterSpec.ofExtract().addIKM(dhSecret).addIKM(remoteSecretKyber).addIKM(localSecretKyber).addSalt(sessionHash.digest()).extractOnly()
            val masterSecret = kdf.deriveData(spec)
            reset()
            masterSecret
        } else null
    }

    override fun startHandshake(): ByteArray? {
        if (!doingHandshake) {
            try {
                handshakeState = IN_PROGRESS
                if (sessionHash == null) {
                    sessionHash = MessageDigest.getInstance("SHA-256")
                }
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
                val kemKyber = KEM.getInstance("ML-KEM")
                decapsulatorKyber = kemKyber.newDecapsulator(keyPairKyber.private)
                val pubKeyDHEnc = keyPairDH.public.encoded
                val pubKeyKyberEnc = keyPairKyber.public.encoded
                return allocateByteBuffer(pubKeyDHEnc.packingSizeWithLength + pubKeyKyberEnc.packingSizeWithLength)
                    .putByteArrayWithLength(pubKeyDHEnc)
                    .putByteArrayWithLength(pubKeyKyberEnc)
                    .array()
                    .also { sessionHash!!.update(it) }
            } catch (e: InvalidKeyException) {
                logger.log(WARNING, DIFFIE_HELLMAN_WITH_KYBER, e)
                reset()
            } catch (e: NoSuchAlgorithmException) {
                logger.log(WARNING, DIFFIE_HELLMAN_WITH_KYBER, e)
                reset()
            }
        }
        return null
    }

    override fun updateAdditionalAuthenticatedData(data: ByteArray) {
        if (sessionHash == null) {
            sessionHash = MessageDigest.getInstance("SHA-256")
        }
        sessionHash!!.update(data)
    }

    override fun reset() {
        remoteSecretKyber = null
        localSecretKyber = null
        keyAgreementDH = null
        decapsulatorKyber = null
        sessionHash = null
        publicKeyDH = null
        publicKeyKyber = null
        handshakeState = UNINITIALIZED
    }

    companion object {
        const val DIFFIE_HELLMAN_WITH_KYBER = "Diffie Hellman Kyber"
    }

}