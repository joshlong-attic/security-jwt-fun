package com.example.jwt;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.MACSigner;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.security.SecureRandom;
import java.util.Date;

@SpringBootApplication
public class JwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtApplication.class, args);
    }

    @Bean
    InMemoryUserDetailsManager authentication() {
        UserDetails one = User.withDefaultPasswordEncoder().username("client1").password("pw").roles("USER").build();
        UserDetails two = User.withDefaultPasswordEncoder().username("client2").password("pw").roles("USER").build();
        return new InMemoryUserDetailsManager(one, two);
    }

    private void joseJwt() throws Exception {
        JWSObject jwsObject = new JWSObject(new JWSHeader(JWSAlgorithm.HS256), new Payload("Hello, world!"));
        byte[] sharedKey = new byte[32];
        new SecureRandom().nextBytes(sharedKey);
        jwsObject.sign(new MACSigner(sharedKey));
        System.out.println(jwsObject.serialize());
    }
}


class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final String jwtAudience;
    private final String jwtIssuer;
    private final String jwtSecret;
    private final String jwtType;

    JwtAuthenticationFilter(AuthenticationManager authenticationManager,
                            String jwtAudience, String jwtIssuer,
                            String jwtSecret, String jwtType) {
        this.jwtAudience = jwtAudience;
        this.jwtIssuer = jwtIssuer;
        this.jwtSecret = jwtSecret;
        this.jwtType = jwtType;
        this.setAuthenticationManager(authenticationManager);
        setFilterProcessesUrl("/api/login");
    }

    @Override
    protected void successfulAuthentication(
            HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain, Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        javax.crypto.SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        String token = Jwts.builder()
                .signWith(secretKey, SignatureAlgorithm.HS512)
                .setHeaderParam("typ", jwtType)
                .setIssuer(jwtIssuer)
                .setAudience(jwtAudience)
                .setSubject(user.getUsername())
                .setExpiration(new Date(System.currentTimeMillis() + 864000000))
                .compact();

        response.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    }

}

@EnableWebSecurity
class JwtSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final String jwtSecret;
    private final String jwtIssuer;
    private final String jwtType;
    private final String jwtAudience;

    JwtSecurityConfiguration(
            @Value("${jwt.secret}") String jwtSecret,
            @Value("${jwt.issuer}") String jwtIssuer,
            @Value("${jwt.type}") String jwtType,
            @Value("${jwt.audience}") String jwtAudience
    ) {
        this.jwtSecret = jwtSecret;
        this.jwtIssuer = jwtIssuer;
        this.jwtType = jwtType;
        this.jwtAudience = jwtAudience;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        var authenticationManager = this.authenticationManager();
        http
                .cors(Customizer.withDefaults())
                .csrf(AbstractHttpConfigurer::disable)
                .addFilter(new JwtAuthenticationFilter(authenticationManager, jwtAudience, jwtIssuer, jwtSecret, jwtType))
                .authorizeRequests(ar ->
                        ar
                                .antMatchers("/**").hasAnyRole("USER")
                                .anyRequest().authenticated()
                )
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    }
}