package com.sterndu.encryption;

import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;

public class DiffieHellman {

	private byte[] secret;
	private KeyAgreement ka;
	private KeyPairGenerator kpg;
	private DHPublicKey publicKey;

	// 0=No Handskate; 1=Doing Handshake; 2=Done Handshake;
	private int handshake_state = 0;

	private DHPublicKey newKey(Object... data) {
		try {
			if (handshake_state != 1) handshake_state=1;
			ka=KeyAgreement.getInstance("DiffieHellman");
			kpg= KeyPairGenerator.getInstance("DiffieHellman");
			kpg.initialize(2048);
			KeyPair keyPair=kpg.generateKeyPair();
			ka.init(keyPair.getPrivate());
			return (DHPublicKey) keyPair.getPublic();
		} catch (InvalidKeyException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			if (data.length == 0) return newKey(1);
			return newKey((int) data[0] + 1);
		}
	}

	public void doPhase(DHPublicKey key,boolean last_phase) {
		try {
			ka.doPhase(key, last_phase);
			if (last_phase) {
				secret=ka.generateSecret();
				handshake_state = 2;
			}
		} catch (InvalidKeyException | IllegalStateException e) {
			e.printStackTrace();
		}
	}

	public byte[] getSecret() {
		if (handshake_state == 2) return secret;
		return null;
	}

	public DHPublicKey getPublicKey() {
		return publicKey!=null?publicKey:(publicKey=newKey());
	}

	public void initialize(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
		if (handshake_state == 1) {
			kpg.initialize(params);
			try {
				KeyPair keyPair=kpg.generateKeyPair();
				ka.init(keyPair.getPrivate());
				publicKey=(DHPublicKey) keyPair.getPublic();
			} catch (InvalidKeyException e) {
				e.printStackTrace();
			}
		}
	}

	public boolean isDoingHandshake() { return handshake_state == 1; }


	public boolean isHandshakeDone() {
		return handshake_state==2;
	}

	public void startHandshake() {
		if (handshake_state!=1) {
			handshake_state=1;
			publicKey = newKey();
		}
	}

}
