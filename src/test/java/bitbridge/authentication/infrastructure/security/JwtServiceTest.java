package bitbridge.authentication.infrastructure.security;

import bitbridge.authentication.exception.InvalidTokenException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.lang.reflect.Field;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtServiceTest {

    @InjectMocks
    private JwtService jwtService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        jwtService = new JwtService();

        setField(jwtService, "jwtSecret", "dGhpc2lzYXZlcnlzZWN1cmVzZWNyZXR0b2tlbmRhdGE2NA==");
        setField(jwtService, "jwtIssuer", "bitbridge.io");
        setField(jwtService, "jwtAudience", "bitbridge-users");
        setField(jwtService, "jwtExpirationMs", 3600000);
    }

    @Test
    void shouldGenerateAndParseValidToken() {
        // given
        var user = new User("john@example.com", "password", List.of(new SimpleGrantedAuthority("ROLE_USER")));
        var auth = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());

        // when
        String token = jwtService.generateJwtToken(auth);
        String username = jwtService.getUsernameFromJwtToken(token);
        boolean valid = jwtService.isValid(token);

        // then
        assertNotNull(token);
        assertEquals("john@example.com", username);
        assertTrue(valid);
    }

    @Test
    void shouldExtractTokenFromAuthorizationHeader() {
        String token = "abc.def.ghi";
        String header = "Bearer " + token;

        String extracted = jwtService.extractToken(header);
        assertEquals(token, extracted);
    }

    @Test
    void shouldReturnNullForMalformedAuthorizationHeader() {
        String header = "InvalidHeader";
        String extracted = jwtService.extractToken(header);
        assertNull(extracted);
    }

    @Test
    void shouldThrowExceptionWhenHeaderIsInvalid() {
        InvalidTokenException ex = assertThrows(InvalidTokenException.class, () ->
                jwtService.extractAndValidateToken("NoBearerTokenHere"));

        assertEquals("Invalid token format", ex.getMessage());
    }

    @Test
    void shouldThrowExceptionWhenTokenIsInvalid() {
        String fakeJwt = "abc.def.ghi";

        InvalidTokenException ex = assertThrows(InvalidTokenException.class, () ->
                jwtService.extractAndValidateToken("Bearer " + fakeJwt));

        assertEquals("Invalid or expired token", ex.getMessage());
    }
    private void setField(Object target, String fieldName, Object value) {
        try {
            Field field = target.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
