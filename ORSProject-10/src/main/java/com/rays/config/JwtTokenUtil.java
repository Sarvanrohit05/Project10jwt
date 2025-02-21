package com.rays.config;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import com.rays.service.JwtUserDetailsService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;


@Component
public class JwtTokenUtil implements Serializable {

	/*
	 * private static final long serialVersionUID = -2550185165626007488L;
	 * 
	 * public static final long JWT_TOKEN_VALIDITY = 5*60*60;
	 * 
	 * @Value("${jwt.secret}") private String secret;
	 * 
	 * public String getUsernameFromToken(String token) { return
	 * getClaimFromToken(token, Claims::getSubject); }
	 * 
	 * public Date getIssuedAtDateFromToken(String token) { return
	 * getClaimFromToken(token, Claims::getIssuedAt); }
	 * 
	 * public Date getExpirationDateFromToken(String token) { return
	 * getClaimFromToken(token, Claims::getExpiration); }
	 * 
	 * public <T> T getClaimFromToken(String token, Function<Claims, T>
	 * claimsResolver) { final Claims claims = getAllClaimsFromToken(token); return
	 * claimsResolver.apply(claims); }
	 * 
	 * private Claims getAllClaimsFromToken(String token) { return
	 * Jwts.parser().setSigningKey(secret).parseClaimsJws(token).getBody(); }
	 * 
	 * private Boolean isTokenExpired(String token) { final Date expiration =
	 * getExpirationDateFromToken(token); return expiration.before(new Date()); }
	 * 
	 * private Boolean ignoreTokenExpiration(String token) { // here you specify
	 * tokens, for that the expiration is ignored return false; } //1 public String
	 * generateToken(UserDetails userDetails) { Map<String, Object> claims = new
	 * HashMap<>(); return doGenerateToken(claims, userDetails.getUsername()); }
	 * 
	 * private String doGenerateToken(Map<String, Object> claims, String subject) {
	 * 
	 * return Jwts.builder().setClaims(claims).setSubject(subject).setIssuedAt(new
	 * Date(System.currentTimeMillis())) .setExpiration(new
	 * Date(System.currentTimeMillis() +
	 * JWT_TOKEN_VALIDITY*1000)).signWith(SignatureAlgorithm.HS512,
	 * secret).compact(); }
	 * 
	 * public Boolean canTokenBeRefreshed(String token) { return
	 * (!isTokenExpired(token) || ignoreTokenExpiration(token)); } //2 public
	 * Boolean validateToken(String token, UserDetails userDetails) { final String
	 * username = getUsernameFromToken(token); return
	 * (username.equals(userDetails.getUsername()) && !isTokenExpired(token)); }
	 */
	@Value("${jwt.secret}")
	private String jwtSecret;

	@Value("${jwt.expiration}")
	private long jwtExpiration;

	@Autowired
	private JwtUserDetailsService userDetailsService;

	public String generateToken(String login) {

		UserDetails userDetails = userDetailsService.loadUserByUsername(login);

		Date now = new Date();
		Date expiration = new Date(now.getTime() + jwtExpiration);
		return Jwts.builder().setSubject(userDetails.getUsername()).setIssuedAt(now).setExpiration(expiration)
				.signWith(SignatureAlgorithm.HS512, jwtSecret).compact();
	}

	public boolean validateToken(String token) {
		try {
			Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token);
			return true;
		} catch (SignatureException e) {
			return false;
		}
	}

	public boolean isTokenExpired(String token) {
		Date expiration = extractExpiration(token);
		return expiration.before(new Date());
	}

	public String extractUsername(String token) {
		return extractClaim(token, Claims::getSubject);
	}

	public Date extractExpiration(String token) {
		return extractClaim(token, Claims::getExpiration);
	}

	private <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
		Claims claims = Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(token).getBody();
		return claimsResolver.apply(claims);
	}
}
