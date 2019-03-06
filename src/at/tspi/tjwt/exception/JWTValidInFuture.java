package at.tspi.tjwt.exception;

public class JWTValidInFuture extends JWTValidationException {
	private static final long serialVersionUID = 1L;
	public JWTValidInFuture() { super(); }
	public JWTValidInFuture(String cause) { super(cause); }
}
