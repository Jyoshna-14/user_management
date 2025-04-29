package com.celcom.user.config;

import java.io.IOException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import jakarta.annotation.Resource;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtAuthenticationFilter extends OncePerRequestFilter {

	public String HEADER_STRING = "Authorization";
	public String AUTHORITIES_KEY = "roles";

	@Resource(name = "userService")
	private UserDetailsService userDetailsService;

	@Autowired
	private TokenProvider jwtTokenUtil;

	@Override
	protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
			throws IOException, ServletException {
		String header = req.getHeader(HEADER_STRING);
		String username = null;
		String authToken = null;
		String userRole = null;
		if (header != null && header.startsWith("celcom")) {
			authToken = header.replace("celcom", "");
			try {
				username = jwtTokenUtil.getUsernameFromToken(authToken);
				userRole = getUserRole(authToken);
			} catch (IllegalArgumentException e) {
				res.setHeader("exceptionName", "TechnicalException");
			} catch (ExpiredJwtException e) {
				res.setHeader("exceptionName", "ExpiredJwtTokenException");
			}
		} else {
			res.setHeader("exceptionName", "InvalidAuthenticationHeaderException");
		}
		if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

			UserDetails userDetails = userDetailsService.loadUserByUsername(username);

			if (jwtTokenUtil.validateToken(authToken, userDetails)) {
				UsernamePasswordAuthenticationToken authentication = jwtTokenUtil.getAuthenticationToken(authToken,
						SecurityContextHolder.getContext().getAuthentication(), userDetails);
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(req));
				logger.info("authenticated user " + username + ", setting security context");
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}
		req.setAttribute("userName", username);
		req.setAttribute("userRole", userRole);

		chain.doFilter(req, res);
	}

	private String getUserRole(String token) {
		final JwtParser jwtParser = Jwts.parser().setSigningKey("signingkey");
		final Jws<Claims> claimsJws = jwtParser.parseClaimsJws(token);
		final Claims claims = claimsJws.getBody();
		final String authorities = claims.get(AUTHORITIES_KEY).toString();
		return authorities;
	}
}
