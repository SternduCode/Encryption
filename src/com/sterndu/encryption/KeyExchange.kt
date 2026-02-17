package com.sterndu.encryption

import com.sterndu.encryption.KeyExchange.HandshakeState.*

abstract class KeyExchange {

    abstract val id: Byte

    enum class HandshakeState {
        UNINITIALIZED,
        IN_PROGRESS,
        DONE;
    }

    protected var handshakeState = UNINITIALIZED

    val doingHandshake: Boolean get() = handshakeState == IN_PROGRESS
    val handshakeDone: Boolean get() = handshakeState == DONE

    abstract fun startHandshake(): ByteArray?

    abstract fun doPhase(data: ByteArray, aad: ByteArray = ByteArray(0)): ByteArray?

    abstract fun getSecret(data: ByteArray): ByteArray?

    abstract fun updateAdditionalAuthenticatedData(data: ByteArray)

    abstract fun reset()

}