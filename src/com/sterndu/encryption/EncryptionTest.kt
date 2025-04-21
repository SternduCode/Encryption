@file:JvmName("EncryptionTest")
package com.sterndu.encryption

import java.io.*
import java.net.InetSocketAddress
import java.nio.channels.SocketChannel
import java.nio.file.Files
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * The Class EncryptionTest.
 */
object EncryptionTest {
	/**
	 * The main method.
	 *
	 * @param args the arguments
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws InvalidKeySpecException the invalid key spec exception
	 * @throws InvalidKeyException the invalid key exception
	 */
	@Throws(
		IOException::class,
		NoSuchAlgorithmException::class,
		InvalidKeySpecException::class,
		InvalidKeyException::class
	)
	@JvmStatic
	fun main(args: Array<String>) {
		val f = File("./ff.txt.enc")
		val password = "FFSSecurePasswordXDD"
		val spec: KeySpec = PBEKeySpec(
			password.toCharArray(), byteArrayOf(
				1, 2, 3
			), 65536, 256
		) // AES-256
		val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
		val key = secretKeyFactory.generateSecret(spec).encoded
		val crypter = CrypterProvider.getCrypterByCode(10)!!
		crypter.makeKey(key)
		if (!f.exists()) {
			f.createNewFile()
			val data = crypter.encrypt("Hello World! FFS".toByteArray(Charsets.UTF_8))
			val fos = FileOutputStream(f)
			fos.write(data)
			fos.close()
		}
		var data = Files.readAllBytes(f.toPath())
		data = crypter.decrypt(data)
		println(data.size)
		println(data.contentToString())
		println(String(data))

		SocketChannel.open().apply {
			configureBlocking(false)
			connect(InetSocketAddress("lin.sterndu.com", 55601))
			finishConnect()

		}

	}
}
