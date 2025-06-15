package bitbridge.authentication.config.handler;

import bitbridge.authentication.infrastructure.security.JwtService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtOAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    @Value("${app.oauth2.redirect-uri}")
    private String redirectUri;
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        String token = jwtService.generateJwtToken(authentication);
        response.sendRedirect( redirectUri+token);
    }
}
