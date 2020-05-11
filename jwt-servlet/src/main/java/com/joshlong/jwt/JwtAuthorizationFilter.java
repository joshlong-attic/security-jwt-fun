package com.joshlong.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.extern.log4j.Log4j2;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@Log4j2
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	private String jwtSecret;

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, String jwtSecret) {
		super(authenticationManager);
		this.jwtSecret = jwtSecret;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws IOException, ServletException {
		UsernamePasswordAuthenticationToken authentication = this.parseToken(request);
		if (authentication != null) {
			SecurityContextHolder.getContext().setAuthentication(authentication);
		}
		else {
			SecurityContextHolder.clearContext();
		}
		filterChain.doFilter(request, response);
	}

	private UsernamePasswordAuthenticationToken parseToken(HttpServletRequest request) {
		String token = request.getHeader(HttpHeaders.AUTHORIZATION);
		String bearerPrefix = "bearer ";
		if (StringUtils.hasText(token) && token.toLowerCase().startsWith(bearerPrefix)) {

			String claims = token.substring(bearerPrefix.length());
			try {
				Jws<Claims> claimsJws = Jwts.parser().setSigningKey(jwtSecret.getBytes()).parseClaimsJws(claims);

				String username = claimsJws.getBody().getSubject();
				if (StringUtils.isEmpty(username)) {
					return null;
				}
				return new UsernamePasswordAuthenticationToken(username, null,
						List.of(new SimpleGrantedAuthority("USER")));
			}
			catch (JwtException exception) {
				log.warn("exception : {} failed : {}", token, exception.getMessage());
			}
		}
		return null;
	}

}
