@file:JvmName("EncryptionTest")
package com.sterndu.encryption

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.nio.file.Files
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.util.*
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
		val f = File("./ff.txt")
		val mpass = "FFSSecurePAsswortXDD"
		val spec: KeySpec = PBEKeySpec(
			mpass.toCharArray(), byteArrayOf(
				1, 2, 3
			), 65536, 256
		) // AES-256
		val secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
		val key = secretKeyFactory.generateSecret(spec).encoded
		val crypter = CrypterList.getByVersion(1)!!
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
		println(Arrays.toString(data))
		println(String(data))
	}
}
