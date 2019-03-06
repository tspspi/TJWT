package at.tspi.tjwt.exception;

public class JWTTimetraveler extends JWTValidationException {
	private static final long serialVersionUID = 1L;
	public JWTTimetraveler() { super(); }
	public JWTTimetraveler(String cause) { super(cause); }
}
