package com.sterndu.encryption

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ceil

object KDF {

	// Basic HKDF implementation (Extract+Expand) TODO Should be replaced by native KDF implementation post J24
	@Throws(Exception::class)
	private fun hkdfSha256(ikm: ByteArray, salt: ByteArray?, info: ByteArray?, length: Int): ByteArray {
		// Step 1: Extract
		var runningSalt = salt
		val mac = Mac.getInstance("HmacSHA256")
		if (runningSalt == null) runningSalt = ByteArray(mac.macLength)
		mac.init(SecretKeySpec(runningSalt, "HmacSHA256"))
		val prk = mac.doFinal(ikm)

		// Step 2: Expand
		val hashLen = mac.macLength
		val n = ceil(length.toDouble() / hashLen).toInt()
		val okm = ByteArray(length)
		var t = ByteArray(0)
		var pos = 0

		for (i in 1..n) {
			mac.init(SecretKeySpec(prk, "HmacSHA256"))
			mac.update(t)
			if (info != null) mac.update(info)
			mac.update(i.toByte())
			t = mac.doFinal()
			System.arraycopy(t, 0, okm, pos, t.size.coerceAtMost(length - pos))
			pos += t.size
		}

		return okm
	}
}