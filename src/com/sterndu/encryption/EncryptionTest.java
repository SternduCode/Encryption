package com.sterndu.encryption;

import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;


// TODO: Auto-generated Javadoc
/**
 * The Class EncryptionTest.
 */
public class EncryptionTest {

	/**
	 * The main method.
	 *
	 * @param args the arguments
	 * @throws IOException Signals that an I/O exception has occurred.
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws InvalidKeySpecException the invalid key spec exception
	 * @throws InvalidKeyException the invalid key exception
	 */
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
		File				f					= new File("./ff.txt");
		String				mpass				= "FFSSecurePAsswortXDD";
		KeySpec				spec				= new PBEKeySpec(mpass.toCharArray(), new byte[] {
				1, 2, 3
		}, 65536, 256);																					// AES-128
		SecretKeyFactory	secretKeyFactory	= SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[]				key					= secretKeyFactory.generateSecret(spec).getEncoded();
		Crypter				cryp				= CrypterList.getByVersion(1);
		cryp.makeKey(key);
		if (!f.exists()) {
			f.createNewFile();
			byte[]				data	= cryp.encrypt(new byte[0]);
			FileOutputStream	fos		= new FileOutputStream(f);
			fos.write(data);
			fos.close();
		}

		byte[] data = Files.readAllBytes(f.toPath());
		data = cryp.decrypt(data);

		System.out.println(data.length);
		System.out.println(Arrays.toString(data));

	}

}
