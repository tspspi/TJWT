package at.tspi.tjwt.exception;

public class JWTValidationException extends Exception {
	private static final long serialVersionUID = 1L;
	public JWTValidationException() { super(); }
	public JWTValidationException(String cause) { super(cause); }
}
