package com.sterndu.encryption;

import java.security.*;

import javax.crypto.*;


// TODO: Auto-generated Javadoc
/**
 * The Class Crypter.
 */
public abstract class Crypter {

	/** The algo. */
	protected String algo;

	/** The c. */
	protected Cipher c;

	/** The secondary key. */
	protected Key key, secondaryKey;

	/**
	 * Instantiates a new crypter.
	 *
	 * @param arg the arg
	 * @throws NoSuchAlgorithmException the no such algorithm exception
	 * @throws NoSuchPaddingException the no such padding exception
	 */
	protected Crypter(String arg) throws NoSuchAlgorithmException, NoSuchPaddingException {
		c		= Cipher.getInstance(arg);
		algo	= arg;
		init();
	}

	/**
	 * Inits the.
	 */
	protected void init() {

	}

	/**
	 * Decrypt.
	 *
	 * @param data the data
	 * @return the byte[]
	 */
	public abstract byte[] decrypt(byte[] data);

	/**
	 * Encrypt.
	 *
	 * @param data the data
	 * @return the byte[]
	 */
	public abstract byte[] encrypt(byte[] data);

	/**
	 * Gets the algorithm.
	 *
	 * @return the algorithm
	 */
	public String getAlgorithm() {
		return algo;
	}

	/**
	 * Gets the cipher.
	 *
	 * @return the cipher
	 */
	public Cipher getCipher() {
		return c;
	}

	/**
	 * Gets the key.
	 *
	 * @return the key
	 */
	public Key getKey() { return key; }

	/**
	 * Gets the secondary key.
	 *
	 * @return the secondary key
	 */
	public Key getSecondaryKey() { return secondaryKey; }

	/**
	 * Make key.
	 *
	 * @param data the data
	 */
	public abstract void makeKey(byte[] data);

	/**
	 * Make secondary key.
	 *
	 * @param data the data
	 */
	public abstract void makeSecondaryKey(byte[] data);

	/**
	 * Sets the key.
	 *
	 * @param key the new key
	 */
	public void setKey(Key key) { this.key = key; }

	/**
	 * Sets the secondary key.
	 *
	 * @param key the new secondary key
	 */
	public void setSecondaryKey(Key key) { secondaryKey = key; }

}
