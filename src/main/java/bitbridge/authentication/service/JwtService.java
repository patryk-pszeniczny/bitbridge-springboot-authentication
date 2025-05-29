package bitbridge.authentication.service;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
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
        String username;
        List<String> roles;
        if(authentication.getPrincipal() instanceof UserDetails userDetails) {
            username = userDetails.getUsername();
            roles = userDetails.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .toList();
        }else if(authentication.getPrincipal() instanceof OAuth2User oAuth2User) {
            username = oAuth2User.getName();
            roles = List.of("ROLE_USER"); // Default role for OAuth2 users
        } else {
            throw new IllegalArgumentException("Unsupported authentication principal type");
        }
        return Jwts.builder()
                .setSubject(username)
                .setIssuer(jwtIssuer)
                .setAudience(jwtAudience)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .claim("roles", roles)
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder().setSigningKey(key()).build()
                .parseClaimsJws(token).getBody().getSubject();
    }
    public String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (headerAuth != null && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7); // obcięcie "Bearer "
        }

        return null;
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            // log
        } catch (ExpiredJwtException e) {
            // log
        } catch (UnsupportedJwtException e) {
            // log
        } catch (IllegalArgumentException e) {
            // log
        }
        return false;
    }
}