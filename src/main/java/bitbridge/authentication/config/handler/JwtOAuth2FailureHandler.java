package bitbridge.authentication.config.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtOAuth2FailureHandler implements AuthenticationFailureHandler {
    @Value("${app.oauth2.failure-redirect-url}")
    private String failureRedirectUrl;
    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception) throws IOException {
        response.sendRedirect(failureRedirectUrl);
    }
}
