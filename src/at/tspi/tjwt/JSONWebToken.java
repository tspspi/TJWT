package at.tspi.tjwt;

import java.lang.reflect.Field;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import at.tspi.tjson.JSONNumber;
import at.tspi.tjson.JSONObject;
import at.tspi.tjson.JSONParser;
import at.tspi.tjson.JSONParserException;
import at.tspi.tjson.JSONSerialize;
import at.tspi.tjson.JSONSerializeException;
import at.tspi.tjson.JSONString;
import at.tspi.tjson.JSONValue;
import at.tspi.tjson.annotations.JSONSerializeValue;
import at.tspi.tjwt.exception.JWTTimetraveler;
import at.tspi.tjwt.exception.JWTTokenExpired;
import at.tspi.tjwt.exception.JWTValidInFuture;
import at.tspi.tjwt.exception.JWTValidationException;

public class JSONWebToken {
	public static final int JWTALGORITHM_HS256 = 0;
	public static final int JWTALGORITHM_HS384 = 1;
	public static final int JWTALGORITHM_HS512 = 2;
	public static final int JWTALGORITHM_RS256 = 3;
	public static final int JWTALGORITHM_RS384 = 4;
	public static final int JWTALGORITHM_RS512 = 5;

	private static final HashMap<Integer, String> hmAlgorithmHeaderNames;
	private static final HashMap<String, Integer> hmAlgorithmHeaderNumbers;
	
	static {
		hmAlgorithmHeaderNames = new HashMap<Integer, String>();

		hmAlgorithmHeaderNames.put(JWTALGORITHM_HS256, "HS256");
		hmAlgorithmHeaderNames.put(JWTALGORITHM_HS384, "HS384");
		hmAlgorithmHeaderNames.put(JWTALGORITHM_HS512, "HS512");
		
		hmAlgorithmHeaderNames.put(JWTALGORITHM_RS256, "RS256");
		hmAlgorithmHeaderNames.put(JWTALGORITHM_RS384, "RS384");
		hmAlgorithmHeaderNames.put(JWTALGORITHM_RS512, "RS512");
		
		hmAlgorithmHeaderNumbers = new HashMap<String, Integer>();
		
		hmAlgorithmHeaderNumbers.put("HS256", JWTALGORITHM_HS256);
		hmAlgorithmHeaderNumbers.put("HS384", JWTALGORITHM_HS384);
		hmAlgorithmHeaderNumbers.put("HS512", JWTALGORITHM_HS512);
		
		hmAlgorithmHeaderNumbers.put("RS256", JWTALGORITHM_RS256);
		hmAlgorithmHeaderNumbers.put("RS384", JWTALGORITHM_RS384);
		hmAlgorithmHeaderNumbers.put("RS512", JWTALGORITHM_RS512);
	}

	private Object payload; // This can be JSONValue or any annotated object
	private boolean signatureValid;

	public JSONWebToken() {
		this.payload = null;
		this.signatureValid = false;
	}
	
	public JSONWebToken(String serialized, List<JWTKey> keyring) throws JSONParserException, JWTValidationException {
		this.signatureValid = false;

		String[] parts = serialized.split("\\.");

		if(parts.length != 3) {
			throw new InvalidParameterException("Missing header, payload or signature - only found "+parts.length+" parts");
		}

		// Keep the signature part
		String signPart = parts[0]+"."+parts[1];

		// Do base64 and JSON decoding
		Base64.Decoder b64Dec = Base64.getDecoder();

		parts[0] = new String(b64Dec.decode((parts[0].replace("-", "+").replace("_", "/"))));
		parts[1] = new String(b64Dec.decode((parts[1].replace("-", "+").replace("_", "/"))));

		// JSON Decode payload and header
		JSONValue jsonValueHeader = JSONParser.parseString(parts[0]);

		if(!(jsonValueHeader instanceof JSONObject)) {
			throw new JSONParserException("JSON object is not a valid JWT header");
		}
		
		JSONObject jsonHeader = (JSONObject)jsonValueHeader;

		{
			JSONValue v = jsonHeader.get("typ");
			if(v == null) {
				throw new JSONParserException("JSON object is not a valid JWT header");
			}
			if(!(v instanceof JSONString)) {
				throw new JSONParserException("JSON object is not a valid JWT header");
			}
			if(!((JSONString)v).get().toUpperCase().equals("JWT")) {
				throw new JSONParserException("JSON object is not a valid JWT header");
			}
		}

		String algorithm = null;
		int algorithmId = -1;
		{
			JSONValue v = jsonHeader.get("alg");
			if(v == null) {
				throw new JSONParserException("JSON object is not a valid JWT header");
			}
			if(!(v instanceof JSONString)) {
				throw new JSONParserException("JSON object is not a valid JWT header");
			}
			if(!hmAlgorithmHeaderNumbers.containsKey(((JSONString)v).get().toUpperCase())) {
				throw new JSONParserException("JWT uses unknown algorithm "+((JSONString)v).get());
			}
			algorithm = ((JSONString)v).get().toUpperCase();
			algorithmId = hmAlgorithmHeaderNumbers.get(algorithm);
		}

		JSONObject jsonPayload = null;
		{
			JSONValue jsonPayloadValue = JSONParser.parseString(parts[1]);
			if(!(jsonPayloadValue instanceof JSONObject)) {
				throw new JSONParserException("Token is not a valid JSON object");				
			}
			jsonPayload = (JSONObject)jsonPayloadValue;
		}

		for(JWTKey currentKey : keyring) {
			// Try until we find a matching key ...
			if(currentKey.getAlgorithm() != algorithmId) {
				continue; // We used another key
			}

			if(currentKey.getIssuer() != null) {
				JSONValue jsonIssuer = jsonPayload.get("iss");
				if(jsonIssuer != null) {
					if(!(jsonIssuer instanceof JSONString)) {
						throw new JSONParserException("Token is not a valid JSON object (Issuer is present but not a string)");
					}

					if(!((JSONString)jsonIssuer).get().equals(currentKey.getIssuer())) {
						continue; // Skip a key with another issuer
					}
				}
			}
			// Now verify the signature according to the key
			switch(algorithmId) {
				case JWTALGORITHM_HS256:
				case JWTALGORITHM_HS384:
				case JWTALGORITHM_HS512:
					String referenceHmac = getHmac(signPart, currentKey.getSharedSecret(), algorithmId)
						.replace('+', '-')
						.replace('/', '_')
						.replace("\r", "")
						.replace("\n", "")
						.replace("=", "");
					this.signatureValid = (stringEqualsO1(parts[2], referenceHmac));
					break;
				case JWTALGORITHM_RS256:
				case JWTALGORITHM_RS384:
				case JWTALGORITHM_RS512:
					byte[] decodedSignature = b64Dec.decode(parts[2].replace('-', '+').replace('_', '/'));
					this.signatureValid = verifyRSASignature(signPart, decodedSignature, currentKey.getPublicKey(), algorithmId);
					break;
				default:
					throw new RuntimeException("Implementation error");
			}

			// Whenever we found an working key - use that ...
			if(this.signatureValid) { break; }
		}

		/*
			Now verify constraints:
				exp		Expires timestamp (unix time)
				nbf		Not before constraint (unix time)
				iat		We check that the token is not a time traveler that comes from the future (most of the time
						this means we have an invalid local clock)

			Note that verifiers always define metadata to be INVALID but NEVER define it to be valid.
		 */
		{
			JSONValue v = jsonPayload.get("exp");
			if(v != null) {
				if(v instanceof JSONNumber) {
					if(((JSONNumber)v).getLong() < (System.currentTimeMillis()/1000L)) {
						throw new JWTTokenExpired();
					}
				} else {
					throw new JSONParserException("exp is not a number");
				}
			}
		}
		
		{
			JSONValue v = jsonPayload.get("nbf");
			if(v != null) {
				if(v instanceof JSONNumber) {
					if(((JSONNumber)v).getLong() > (System.currentTimeMillis()/1000L)) {
						throw new JWTValidInFuture();
					}
				} else {
					throw new JSONParserException("nbf is not a number");
				}
			}
		}
		
		{
			JSONValue v = jsonPayload.get("iat");
			if(v != null) {
				if(v instanceof JSONNumber) {
					if(((JSONNumber)v).getLong() > (System.currentTimeMillis()/1000L)) {
						throw new JWTTimetraveler();
					}
				} else {
					throw new JSONParserException("iat is not a number");
				}
			}
		}

		// ToDo: Should we potentially unserialize into a given object / support that?
		// Would be a nice feature ...
		this.payload = jsonPayload;
	}

	public boolean isValid() {
		return this.signatureValid;
	}

	private boolean reflectSetJSONField(Object target, String fieldName, Object valueAndType) throws IllegalAccessException {
		@SuppressWarnings("rawtypes")
		Class targetClass = target.getClass();
		boolean bWritten = false;

		while(targetClass != null) {
			Field[] allFields = targetClass.getDeclaredFields();
			for(Field field : allFields) {
				JSONSerializeValue jsonAnnotation = field.getAnnotation(JSONSerializeValue.class);
				if(!(jsonAnnotation instanceof JSONSerializeValue)) {
					continue; // Skip un annotated fields (they wont be serialized later on
				}

				if(jsonAnnotation.name().equals(fieldName)) {
					boolean bWasAccessible = field.isAccessible();
					field.setAccessible(true);
					field.set(target, valueAndType);
					field.setAccessible(bWasAccessible);
					bWritten = true;
					break;
				} else {
					if(field.getName().equals(fieldName)) {
						boolean bWasAccessible = field.isAccessible();
						field.setAccessible(true);
						field.set(target, valueAndType);
						field.setAccessible(bWasAccessible);
						bWritten = true;
						break;
					}
				}
			}
			
			// If not found in this class ... continue in superclass
			if(bWritten) {
				break;
			}
			targetClass.getSuperclass();
		}

		return bWritten;
	}

	public String signToken(List<JWTKey> keyData, int keyIndex) throws JSONSerializeException, IllegalAccessException {
		if((keyIndex < 0) || (keyIndex >= keyData.size())) {
			throw new InvalidParameterException("Key index out of range");
		}
		if(!verifyAlgorithmID(keyData.get(keyIndex).getAlgorithm())) {
			throw new InvalidParameterException("Unknown algorithm for selected key");
		}

		/*
			Set the following fields in our payload:
				iss				Issuer (only if present in key material)
				iat				Issued at (always)
		 */

		if(payload == null) {
			// These tokens wont make much sense but we support creating "empty" tokens
			payload = new JSONObject();
		}

		if(payload instanceof JSONValue) {
			if(!(payload instanceof JSONObject)) {
				throw new InvalidParameterException("Inner payload has to be a JSONObject");
			}

			if(keyData.get(keyIndex).getIssuer() != null) { ((JSONObject)payload).put("iss", new JSONString(keyData.get(keyIndex).getIssuer())); }
			((JSONObject)payload).put("iat", new JSONNumber(System.currentTimeMillis()/1000L));
		} else {
			// Use reflection to write fields
			if(keyData.get(keyIndex).getIssuer() != null) { reflectSetJSONField(payload, "iss", keyData.get(keyIndex).getIssuer()); }
			reflectSetJSONField(payload, "iat", new Long(System.currentTimeMillis()/1000L));
		}

		// Build our serialized payload
		String jsonPayload;
		if(payload instanceof JSONValue) {
			jsonPayload = JSONSerialize.toJSONString((JSONValue)this.payload);
		} else {
			jsonPayload = JSONSerialize.toJSONString(this.payload);
		}

		Base64.Encoder b64enc = Base64.getEncoder();
		jsonPayload = b64enc
			.encodeToString(jsonPayload.getBytes())
			.replace('+', '-')
			.replace('/', '_')
			.replace("\r", "")
			.replace("\n", "")
			.replace("=", "");

		// Build our header
		String jwtHeader = "{\"typ\":\"JWT\",\"alg\":\""+hmAlgorithmHeaderNames.get(keyData.get(keyIndex).getAlgorithm())+"\"}";
		jwtHeader = b64enc
			.encodeToString(jwtHeader.getBytes())
			.replace('+', '-')
			.replace('/', '_')
			.replace("\r", "")
			.replace("\n", "")
			.replace("=", "");

		// Now create our signature
		String signature = null;

		switch(keyData.get(keyIndex).getAlgorithm()) {
			case JWTALGORITHM_HS256:
			case JWTALGORITHM_HS384:
			case JWTALGORITHM_HS512:
				signature = getHmac(jwtHeader+"."+jsonPayload, keyData.get(keyIndex).getSharedSecret(), keyData.get(keyIndex).getAlgorithm())
					.replace('+', '-')
					.replace('/', '_')
					.replace("\r", "")
					.replace("\n", "")
					.replace("=", "");
				break;
			case JWTALGORITHM_RS256:
			case JWTALGORITHM_RS384:
			case JWTALGORITHM_RS512:
				signature = getRSASignature(jwtHeader+"."+jsonPayload, keyData.get(keyIndex).getPrivateKey(), keyData.get(keyIndex).getAlgorithm())
					.replace('+', '-')
					.replace('/', '_')
					.replace("\r", "")
					.replace("\n", "")
					.replace("=", "");
				break;
			default:
				throw new InvalidParameterException("Unknown algorithm");
		}

		return jwtHeader+"."+jsonPayload+"."+signature;
	}

	public Object getPayload() { return this.payload; }
	public JSONWebToken setPayload(Object o) { this.payload = o; return this; }

	/*
		Some static helper methods
	 */

	private static boolean verifyAlgorithmID(int alg) {
		switch(alg) {
			case JWTALGORITHM_HS256:
			case JWTALGORITHM_HS384:
			case JWTALGORITHM_HS512:
			case JWTALGORITHM_RS256:
			case JWTALGORITHM_RS384:
			case JWTALGORITHM_RS512:
				return true;
			default:
					return false;
		}
	}

	private static String getHmac(String payload, String sharedSecret, int algorithm) {
		String strAlgorithm;
		switch(algorithm) {
			case JWTALGORITHM_HS256:	strAlgorithm = "HmacSHA256"; break;
			case JWTALGORITHM_HS384:	strAlgorithm = "HmacSHA384"; break;
			case JWTALGORITHM_HS512:	strAlgorithm = "HmacSHA512"; break;
			default:
				throw new InvalidParameterException("Unsupported HMAC algorithm identifier"); 
		}
		SecretKeySpec sks = new SecretKeySpec(sharedSecret.getBytes(), strAlgorithm);
		try {
			Mac mac = Mac.getInstance(strAlgorithm);
			mac.init(sks);
			
			Base64.Encoder b64enc = Base64.getEncoder();
			return b64enc.encodeToString(mac.doFinal(payload.getBytes()));
		} catch(NoSuchAlgorithmException e) {
			return null;
		} catch(InvalidKeyException e){
			return null;
		}
	}
	private static String getRSASignature(String payload, PrivateKey privKey, int algorithm) {
		try {
			String strAlgorithm;
			switch(algorithm) {
				case JWTALGORITHM_RS256:	strAlgorithm = "SHA256withRSA"; break;
				case JWTALGORITHM_RS384:	strAlgorithm = "SHA384withRSA"; break;
				case JWTALGORITHM_RS512:	strAlgorithm = "SHA512withRSA"; break;
				default:
					throw new InvalidParameterException("Unsupported RSA algorithm identifier"); 
			}
	
			Signature newSig = Signature.getInstance(strAlgorithm);
			newSig.initSign(privKey);
			newSig.update(payload.getBytes());
			
			Base64.Encoder b64enc = Base64.getEncoder();
			return b64enc.encodeToString(newSig.sign());
		} catch(NoSuchAlgorithmException e) {
			return null;
		} catch(InvalidKeyException e) {
			return null;
		} catch(SignatureException e) {
			return null;
		}
	}
	private static boolean verifyRSASignature(String payload, byte[] signature, PublicKey pubKey, int algorithm) {
		try {
			String strAlgorithm;
			switch(algorithm) {
				case JWTALGORITHM_RS256:	strAlgorithm = "SHA256withRSA"; break;
				case JWTALGORITHM_RS384:	strAlgorithm = "SHA384withRSA"; break;
				case JWTALGORITHM_RS512:	strAlgorithm = "SHA512withRSA"; break;
				default:
					throw new InvalidParameterException("Unsupported RSA algorithm identifier"); 
			}
	
			Signature sig;
			sig = Signature.getInstance(strAlgorithm);
			sig.initVerify(pubKey);
			sig.update(payload.getBytes());

			return sig.verify(signature);
		} catch (NoSuchAlgorithmException e) {
			return false;
		} catch (InvalidKeyException e) {
			return false;
		} catch (SignatureException e) {
			return false;
		}
	}

	private static boolean stringEqualsO1(String a, String b) {
		boolean bSame = true;

		if(a.length() != b.length()) { return false; }

		for(int i = 0; i < a.length(); i++) {
			bSame = bSame & (a.charAt(i) == b.charAt(i));
		}
		
		return bSame;
	}
}
