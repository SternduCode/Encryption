package com.sterndu.encryption.ssllike;

import java.io.IOException;
import java.net.*;

public class SecureServerSocket extends ServerSocket {

	private String aescipher = "AES", rsacipher = "RSA";

	public SecureServerSocket() throws IOException {
	}

	public SecureServerSocket(int port) throws IOException {
		super(port);
	}

	public SecureServerSocket(int port, int backlog) throws IOException {
		super(port, backlog);
	}

	public SecureServerSocket(int port, int backlog, InetAddress bindAddr) throws IOException {
		super(port, backlog, bindAddr);
	}

	@Override
	public Socket accept() throws IOException {
		if (isClosed())
			throw new SocketException("Socket is closed");
		if (!isBound())
			throw new SocketException("Socket is not bound yet");
		SecureSocket s = new SecureSocket((SocketImpl) null);
		s.setAESCipherText(aescipher);
		s.setRSACipherText(rsacipher);
		implAccept(s);
		return s;
	}

	public void setAESCipherText(String ciphertext) { aescipher = ciphertext; }
	public void setRSACipherText(String ciphertext) { rsacipher = ciphertext; }

}
