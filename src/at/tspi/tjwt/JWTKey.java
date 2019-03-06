package at.tspi.tjwt;

import java.security.InvalidParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class JWTKey {
	private int algorithm;		// This has to be one of the JSONWebToken values
	private String issuer;		// Content of "iss" field

	private String sharedSecret; // Used for HMAC based signatures
	private PrivateKey pkPrivate; // Private key for RSA
	private PublicKey pkPublic; // Public key for RSA

	public JWTKey(int algorithm, String issuer) {
		this.algorithm = algorithm;
		this.issuer = issuer;

		this.sharedSecret = null;

		this.pkPrivate = null;
		this.pkPublic = null;
	}

	// ToDo: Add Member for RSA keypairs (private is of course NOT loaded on the remote side)

	public String getIssuer() { return this.issuer; }
	public JWTKey setIssuer(String issuer) { this.issuer = issuer; return this; }
	public int getAlgorithm() { return this.algorithm; }

	public String getSharedSecret() { return this.sharedSecret; }
	public JWTKey setSharedSecret(String sharedSecret) { this.sharedSecret = sharedSecret; return this; }

	public PrivateKey getPrivateKey() { return this.pkPrivate; }
	public PublicKey getPublicKey() { return this.pkPublic; }
	public JWTKey setPrivateKey(PrivateKey pk) { this.pkPrivate = pk; return this; }
	public JWTKey setPublicKey(PublicKey pk) { this.pkPublic = pk; return this; }

	public JWTKey setPrivateKey(byte[] b) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec pkcs8ks = new PKCS8EncodedKeySpec(b);
		this.pkPrivate = kf.generatePrivate(pkcs8ks);
		return this;
	}

	public JWTKey setPublicKey(byte[] b) throws NoSuchAlgorithmException, InvalidKeySpecException {
		KeyFactory kf = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec ks = new X509EncodedKeySpec(b);
		this.pkPublic = kf.generatePublic(ks);
		return this;
	}

	public byte[] getPublicKeyBytes() {
		X509EncodedKeySpec x509ks = new X509EncodedKeySpec(this.pkPublic.getEncoded());
		return x509ks.getEncoded();
	}
	public byte[] getPrivateKeyBytes() {
		PKCS8EncodedKeySpec pkcs8ks = new PKCS8EncodedKeySpec(this.pkPrivate.getEncoded());
		return pkcs8ks.getEncoded();
	}

	public String toString() {
		StringBuilder builder = new StringBuilder();

		switch(this.algorithm) {
			case JSONWebToken.JWTALGORITHM_HS256:	builder.append("HMAC, 256 Bit; "); 		break;
			case JSONWebToken.JWTALGORITHM_HS384:	builder.append("HMAC, 384 Bit; "); 		break;
			case JSONWebToken.JWTALGORITHM_HS512:	builder.append("HMAC, 512 Bit; "); 		break;
			case JSONWebToken.JWTALGORITHM_RS256:	builder.append("RSA, 256 Bit; "); 		break;
			case JSONWebToken.JWTALGORITHM_RS384:	builder.append("RSA, 384 Bit; "); 		break;
			case JSONWebToken.JWTALGORITHM_RS512:	builder.append("RSA, 512 Bit; "); 		break;
			default:								builder.append("UnknownAlgorithm "); 	break;
		}

		if(this.issuer != null) {
			if(!this.issuer.equals("")) {
				builder.append("Issuer \""+this.issuer+"\"; ");
			}
		}

		if(this.sharedSecret != null) {
			builder.append("Shared secret: "+this.sharedSecret+"; ");
		}
		if(this.pkPrivate != null) {
			builder.append("Private key: "+this.pkPrivate.toString()+"; ");
		}
		if(this.pkPublic != null) {
			builder.append("Public  key: "+this.pkPublic.toString()+"; ");
		}
		
		return builder.toString();
	}

	public static JWTKey createRSAKey(int hashlength, int keylength, String issuer) throws NoSuchAlgorithmException {
		if((hashlength!= 256) && (hashlength != 384) && (hashlength != 512)) {
			throw new InvalidParameterException("Unsupported hash length");
		}

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(keylength, new SecureRandom());

		KeyPair rsaKeyPair = kpg.generateKeyPair();

		JWTKey newKey;
		switch(hashlength) {
			case 256:	newKey = new JWTKey(JSONWebToken.JWTALGORITHM_RS256, issuer); break;
			case 384:	newKey = new JWTKey(JSONWebToken.JWTALGORITHM_RS384, issuer); break;
			case 512:	newKey = new JWTKey(JSONWebToken.JWTALGORITHM_RS512, issuer); break;
			default: throw new RuntimeException("Implementation error");
		}

		newKey.setPublicKey(rsaKeyPair.getPublic());
		newKey.setPrivateKey(rsaKeyPair.getPrivate());

		return newKey;
	}

}
