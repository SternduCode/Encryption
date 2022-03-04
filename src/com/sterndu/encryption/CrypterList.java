package com.sterndu.encryption;

import java.io.IOException;
import java.nio.*;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public abstract class CrypterList implements Comparable<CrypterList> {

	private static Map<Integer,CrypterList>versions=new HashMap<>();
	static {
		try {
			versions.put(1, new CrypterList(1) {

				private final Crypter[] crypters = new Crypter[] {
						new Crypter("AES_256/GCM/NoPadding") {

							@Override
							public byte[] decrypt(byte[] data) {
								if (key != null) try {
									int length = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN).getInt(0);
									byte[] params = Arrays.copyOfRange(data, 4, length + 4);
									AlgorithmParameters aesParams = AlgorithmParameters.getInstance("GCM");
									aesParams.init(params);
									data = Arrays.copyOfRange(data, 4 + length, data.length);
									// System.out.println(data.length + " " + Arrays.toString(data));
									c.init(Cipher.DECRYPT_MODE, key, aesParams);
									data = c.doFinal(data);
									return data;
								} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
										| NoSuchAlgorithmException
										| IOException | InvalidAlgorithmParameterException e) {
									e.printStackTrace();
								}
								return new byte[0];
							}

							@Override
							public byte[] encrypt(byte[] data) {
								if (key != null) try {
									c.init(Cipher.ENCRYPT_MODE, key);
									data = c.doFinal(data);
									byte[] spec = c.getParameters().getEncoded();
									byte[] length_bytes = ByteBuffer.allocate(4).putInt(spec.length).array();
									byte[] ret = new byte[4 + spec.length + data.length];
									// System.out.println(data.length + " " + Arrays.toString(data));
									System.arraycopy(length_bytes, 0, ret, 0, 4);
									System.arraycopy(spec, 0, ret, 4, spec.length);
									System.arraycopy(data, 0, ret, 4 + spec.length, data.length);
									return ret;
								} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException
										| IOException e) {
									e.printStackTrace();
								}
								return new byte[0];
							}

							@Override
							public void makeKey(byte[] data) {
								key = new SecretKeySpec(data, 0, 32, "AES");
							}
						}
				};
				{
					mode0=crypters[0];
					mode1=crypters[0];
					mode2=crypters[0];
				}

				@Override
				public Crypter[] getAll() { return crypters; }

				@Override
				public Crypter getByMode(byte mode) {
					Crypter c = super.getByMode(mode);
					if (c == null) return switch (mode) {
						default -> null;
					};
					else return c;
				}

			});
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	protected Crypter mode0, mode1, mode2;

	private final int want;

	public CrypterList() {
		want = 0;
	}

	public CrypterList(Integer want) {
		this.want=want;
	}

	public static CrypterList getByVersion(int v) {
		return versions.get(v);
	}

	public static int[] getSupportedVersions() { return versions.keySet().parallelStream().mapToInt(i -> i).toArray(); }

	@Override
	public int compareTo(CrypterList o) {
		return Integer.compare(want, o.want);
	}

	public abstract Crypter[] getAll();

	/**
	 *
	 * @param mode the mode to get the {@code Crypter} from
	 *
	 * @return the {@code Crypter} of the specified mode {@code 0 = balanced/mixed }
	 *         {@code  1 = high bandwidth } {@code  2 = high security}
	 *
	 */
	public Crypter getByMode(byte mode) {
		return switch (mode) {
			case 0 -> mode0;
			case 1 -> mode1;
			case 2 -> mode2;
			default -> null;
		};
	}

}
