package com.sterndu.encryption;

import java.security.*;
import javax.crypto.*;


public abstract class Crypter {

	protected String algo;
	protected Cipher c;
	protected Key key;

	protected Crypter(String arg) {
		try {
			c = Cipher.getInstance(arg);
			algo = arg;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
	}

	public abstract byte[] decrypt(byte[] data);

	public abstract byte[] encrypt(byte[] data);

	public String getAlgorithm() {
		return algo;
	}

	public Cipher getCipher() {
		return c;
	}

	public Key getKey() { return key; }

	public abstract void makeKey(byte[] data);

	public void setKey(Key key) { this.key = key; }

}
