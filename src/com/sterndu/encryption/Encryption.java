package com.sterndu.encryption;

import java.security.InvalidKeyException;
import javax.crypto.*;

public interface Encryption {

	byte[] decrypt(byte[] encrypteddata) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

	byte[] encrypt(byte[] data) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException;

	Crypter getCrypter();
	// TODO SSL Like + DiffieHellman
}
