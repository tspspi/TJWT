package at.tspi.tjwt.exception;

public class JWTTokenExpired extends JWTValidationException {
	private static final long serialVersionUID = 1L;
	public JWTTokenExpired() { super(); }
	public JWTTokenExpired(String cause) { super(cause); }
}
