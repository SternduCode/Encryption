package com.sterndu.encryption;

import java.nio.*;
import java.security.*;
import java.util.*;
import java.util.function.Supplier;

import javax.crypto.*;
import javax.crypto.spec.*;

// TODO: Auto-generated Javadoc
/**
 * The Class CrypterList.
 */
public class CrypterList {

	/** The versions. */
	private static Map<Integer, Supplier<Crypter>> versions = new HashMap<>();
	static {
		try {
			Cipher.getInstance("AES/GCM/NoPadding");
			versions.put(1, (Supplier<Crypter>) () -> {
				try {
					return new Crypter("AES/GCM/NoPadding") {

						@Override
						public byte[] decrypt(byte[] data) {
							if (key != null) try {
								int					length		= ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).getInt(0);
								byte[]				iv			= Arrays.copyOfRange(data, 4, length + 4);
								GCMParameterSpec	aesParams	= new GCMParameterSpec(128, iv);
								data = Arrays.copyOfRange(data, 4 + length, data.length);
								// System.out.println(data.length + " " + Arrays.toString(data));
								c.init(Cipher.DECRYPT_MODE, key, aesParams);
								return c.doFinal(data);
							} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
									| InvalidAlgorithmParameterException e) {
								e.printStackTrace();
							}
							return new byte[0];

						}

						@Override
						public byte[] encrypt(byte[] data) {
							if (key != null) try {
								byte[] iv = new byte[12];
								new SecureRandom().nextBytes(iv);
								c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
								data = c.doFinal(data);
								byte[]	length_bytes	= ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(iv.length).array();
								byte[]	ret				= new byte[4 + iv.length + data.length];
								// System.out.println(data.length + " " + Arrays.toString(data));
								System.arraycopy(length_bytes, 0, ret, 0, 4);
								System.arraycopy(iv, 0, ret, 4, iv.length);
								System.arraycopy(data, 0, ret, 4 + iv.length, data.length);
								return ret;
							} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
									| InvalidAlgorithmParameterException e) {
								e.printStackTrace();
							}
							return new byte[0];

						}

						@Override
						public void makeKey(byte[] data) throws InvalidKeyException {
							if (data.length != 32 && data.length != 16)
								throw new InvalidKeyException("The key material that was supplied was of wrong length");
							key = new SecretKeySpec(data, 0, 32, "AES");

						}

						@Override
						public void makeSecondaryKey(byte[] data) {}

					};
				} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
					e.printStackTrace();
					return null;
				}
			});
		} catch (Exception e) {}

		try {
			Cipher.getInstance("ChaCha20-Poly1305");
			versions.put(20, (Supplier<Crypter>) () -> {
				try {
					return new Crypter("ChaCha20-Poly1305") {

						@Override
						public byte[] decrypt(byte[] data) {
							if (key != null) try {
								int					length		= ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).getInt(0);
								byte[]			nonce		= Arrays.copyOfRange(data, 4, length + 4);
								IvParameterSpec	aesParams	= new IvParameterSpec(nonce);
								data = Arrays.copyOfRange(data, 4 + length, data.length);
								// System.out.println(data.length + " " + Arrays.toString(data));
								c.init(Cipher.DECRYPT_MODE, key, aesParams);
								return c.doFinal(data);
							} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
									| InvalidAlgorithmParameterException e) {
								e.printStackTrace();
							}
							return new byte[0];

						}

						@Override
						public byte[] encrypt(byte[] data) {
							if (key != null) try {
								byte[] nonce = new byte[12];
								new SecureRandom().nextBytes(nonce);
								c.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(nonce));
								data = c.doFinal(data);
								byte[]	length_bytes	= ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(nonce.length).array();
								byte[]	ret				= new byte[4 + nonce.length + data.length];
								// System.out.println(data.length + " " + Arrays.toString(data));
								System.arraycopy(length_bytes, 0, ret, 0, 4);
								System.arraycopy(nonce, 0, ret, 4, nonce.length);
								System.arraycopy(data, 0, ret, 4 + nonce.length, data.length);
								return ret;
							} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
									| InvalidAlgorithmParameterException e) {
								e.printStackTrace();
							}
							return new byte[0];

						}

						@Override
						public void makeKey(byte[] data) { key = new SecretKeySpec(data, 0, 32, "ChaCha20"); }

						@Override
						public void makeSecondaryKey(byte[] data) {}

					};
				} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
					e.printStackTrace();
					return null;
				}
			});
		} catch (Exception e) {}
	}

	/**
	 * Gets the by version.
	 *
	 * @param v the v
	 * @return the by version
	 */
	public static Crypter getByVersion(int v) { return versions.get(v).get();
	}

	/**
	 * Gets the supported versions.
	 *
	 * @return the supported versions
	 */
	public static int[] getSupportedVersions() { return versions.keySet().parallelStream().mapToInt(i -> i).toArray(); }

}
