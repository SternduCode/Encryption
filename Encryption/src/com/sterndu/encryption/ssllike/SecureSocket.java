package com.sterndu.encryption.ssllike;

import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.Cipher;
import com.sterndu.encryption.Crypter;

public class SecureSocket extends Socket {

	private String aesciphert = "AES", rsacipher = "RSA";
	private int handshake = 0;
	private Key aeskey;
	private Cipher aescipher;
	private Crypter aesc, rsac;


	public SecureSocket(InetAddress address, int port) throws IOException {
		super(address, port);
	}

	public SecureSocket(InetAddress address, int port, InetAddress localAddr, int localPort) throws IOException {
		super(address, port, localAddr, localPort);
	}

	public SecureSocket(Proxy proxy) {
		super(proxy);
	}

	public SecureSocket(SocketImpl impl) throws SocketException {
		super(impl);
	}

	public SecureSocket(String host, int port) throws UnknownHostException, IOException {
		super(host, port);
	}

	public SecureSocket(String host, int port, InetAddress localAddr, int localPort) throws IOException {
		super(host, port, localAddr, localPort);
	}

	public byte[] read() throws IOException {
		InputStream is = getInputStream();
		while (is.available() == 0) try {
			Thread.sleep(1);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		while (is.available() > 0) {
			byte[] b = new byte[512];
			baos.write(b, 0, is.read(b));
		}
		return aesc.decrypt(baos.toByteArray());
	}

	public void setAESCipherText(String ciphertext) {
		aesciphert = ciphertext;
		aesc = new Crypter(ciphertext) {

			@Override
			public byte[] decrypt(byte[] data) {
				return null;
			}

			@Override
			public byte[] encrypt(byte[] data) {
				return null;
			}

			@Override
			public void makeKey(byte[] data) {}

		};
	}

	public void setRSACipherText(String ciphertext) {
		rsacipher = ciphertext;
		rsac = new Crypter(ciphertext) {

			@Override
			public byte[] decrypt(byte[] data) {
				return null;
			}

			@Override
			public byte[] encrypt(byte[] data) {
				return null;
			}

			@Override
			public void makeKey(byte[] data) {}

		};
	}

	public void startHandShake() {
		//TODO rehandshake
		handshake = -1;
		try {
			KeyPair kp=KeyPairGenerator.getInstance("RSA").generateKeyPair();

		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	public boolean write(byte[] b) {
		boolean bo = false;
		if (handshake == 1) {
			b = aesc.encrypt(b);
			bo = true;
		}
		try {
			getOutputStream().write(b);
			getOutputStream().flush();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return bo;
	}


}
