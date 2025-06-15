package bitbridge.authentication.infrastructure.security;

import bitbridge.authentication.exception.InvalidTokenException;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.List;

@Service
public class JwtService {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration-ms}")
    private int jwtExpirationMs;

    @Value("${app.jwt.issuer}")
    private String jwtIssuer;

    @Value("${app.jwt.audience}")
    private String jwtAudience;

    public String generateJwtToken(Authentication authentication) {
        String username = resolveUsername(authentication);
        List<String> roles = resolveRoles(authentication);

        return Jwts.builder()
                .setSubject(username)
                .setIssuer(jwtIssuer)
                .setAudience(jwtAudience)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .claim("roles", roles)
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String getUsernameFromJwtToken(String token) {
        return parseClaims(token).getSubject();
    }
    public String extractToken(String headerAuth) {
        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7);
        }
        return null;
    }
    public String extractAndValidateToken(String headerValue) {
        String token = extractToken(headerValue);
        if (token == null) {
            throw new InvalidTokenException("Invalid token format");
        }
        if (!isValid(token)) {
            throw new InvalidTokenException("Invalid or expired token");
        }
        return getUsernameFromJwtToken(token);
    }
    public boolean isValid(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }
    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    private String resolveUsername(Authentication authentication) {
        if (authentication.getPrincipal() instanceof UserDetails userDetails) {
            return userDetails.getUsername();
        } else if (authentication.getPrincipal() instanceof OAuth2User oAuth2User) {
            return oAuth2User.getName();
        } else {
            return authentication.getName();
        }
    }
    private List<String> resolveRoles(Authentication authentication) {
        if (authentication.getPrincipal() instanceof UserDetails userDetails) {
            return userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
        } else {
            return List.of("USER");
        }
    }
}