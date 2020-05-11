package com.example.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.log4j.Log4j2;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Log4j2
@SpringBootApplication
public class JwtApplication {


    public static void main(String[] args) {
        SpringApplication.run(JwtApplication.class, args);
    }

    @Bean
    InMemoryUserDetailsManager authentication() {
        UserDetails one = User.withDefaultPasswordEncoder()
                .username("client1").password("pw").roles("USER")
                .build();
        UserDetails two = User.withDefaultPasswordEncoder()
                .username("client2").password("pw").roles("USER")
                .build();
        return new InMemoryUserDetailsManager(one, two);
    }
}


@RestController
class GreetingsRestController {

    @GetMapping("/hello")
    Map<String, String> greet(@AuthenticationPrincipal Principal principal) {
        return Map.of("greetings", "hello " + principal.getName() + "!");
    }
}


/*
 * Taken from <a href="https://grobmeier.solutions/spring-security-5-jwt-basic-auth.html">this interesting article</a>.
 */
@Log4j2
class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final String jwtAudience;
    private final String jwtIssuer;
    private final String jwtSecret;
    private final String jwtType;

    JwtAuthenticationFilter(
            AuthenticationManager authenticationManager,
            String jwtAudience, String jwtIssuer,
            String jwtSecret, String jwtType) {
        this.jwtAudience = jwtAudience;
        this.jwtIssuer = jwtIssuer;
        this.jwtSecret = jwtSecret;
        this.jwtType = jwtType;
        this.setAuthenticationManager(authenticationManager);
        setFilterProcessesUrl("/api/login");
    }

   /*
    @Override
    @SneakyThrows
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain, Authentication authentication) {

        JWSHeader jwsHeader = new JWSHeader.Builder(JWSAlgorithm.HS256)
                .type(JOSEObjectType.JWT)
                .contentType(MediaType.APPLICATION_JSON_VALUE)
                .build();
        JWSObject jwsObject = new JWSObject(jwsHeader, new Payload("Hello, world!"));
        jwsObject.sign(new MACSigner(jwtSecret));
        String token = jwsObject.serialize();
        response.addHeader(HttpHeaders.AUTHORIZATION, "Bearer " + token);
    }
    */


    @Override
    protected void successfulAuthentication(
            HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain, Authentication authentication) {
        User user = (User) authentication.getPrincipal();
        javax.crypto.SecretKey secretKey = Keys.hmacShaKeyFor(jwtSecret.getBytes());
        String token = Jwts
                .builder()
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

@Log4j2
class JwtAuthorizationFilter extends BasicAuthenticationFilter {


    private String jwtSecret;
    private String jwtIssuer;
    private String jwtType;
    private String jwtAudience;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager,
                                  String jwtAudience, String jwtIssuer, String jwtSecret, String jwtType) {
        super(authenticationManager);

        this.jwtAudience = jwtAudience;
        this.jwtIssuer = jwtIssuer;
        this.jwtSecret = jwtSecret;
        this.jwtType = jwtType;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws IOException, ServletException {

        UsernamePasswordAuthenticationToken authentication = parseToken(request);

        if (authentication != null) {
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } else {
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private UsernamePasswordAuthenticationToken parseToken(HttpServletRequest request) {
        String token = request.getHeader(HttpHeaders.AUTHORIZATION);
        String bearerPrefix = "bearer ";
        if (StringUtils.hasText(token) &&
                token.toLowerCase().startsWith(bearerPrefix)) {

            String claims = token.substring(bearerPrefix.length());
//            String claims = token.replace("Bearer ", "").trim();
            try {

                Jws<Claims> claimsJws = Jwts
                        .parser()
                        .setSigningKey(jwtSecret.getBytes())
                        .parseClaimsJws(claims);

                String username = claimsJws.getBody().getSubject();
                if (StringUtils.isEmpty(username)) {
                    return null;
                }

                return new UsernamePasswordAuthenticationToken(username, null, List.of(new SimpleGrantedAuthority("USER")));

            } catch (JwtException exception) {
                log.warn("Some exception : {} failed : {}", token, exception.getMessage());
            }
        }
        return null;
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
                .addFilter(new JwtAuthorizationFilter(authenticationManager, jwtAudience, jwtIssuer, jwtSecret, jwtType))
                .authorizeRequests(ar ->
                                ar
//                                .antMatchers("/hello").authenticated()
                                        .anyRequest().authenticated()
                )
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
    }
}