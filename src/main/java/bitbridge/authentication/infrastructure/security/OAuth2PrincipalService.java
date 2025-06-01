package bitbridge.authentication.infrastructure.security;

import bitbridge.authentication.application.service.UserService;
import bitbridge.authentication.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.*;

@Service
@RequiredArgsConstructor
public class OAuth2PrincipalService extends DefaultOAuth2UserService {

    private final UserService userService;
    private final RestTemplate restTemplate = new RestTemplate();
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        try {
            Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());
            if ("github".equals(userRequest.getClientRegistration().getRegistrationId())) {
                githubEmail(userRequest, attributes);
            }
            User user = userService.processOAuth2User(userRequest, oAuth2User, attributes);
            return new OAuth2UserPrincipal(user, attributes);
        } catch (Exception ex) {
            throw new OAuth2AuthenticationException(ex.getMessage());
        }
    }
    public void githubEmail(OAuth2UserRequest userRequest, Map<String, Object> attributes) {
        String token = userRequest.getAccessToken().getTokenValue();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        HttpEntity<Void> entity = new HttpEntity<>(headers);

        ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                "https://api.github.com/user/emails",
                HttpMethod.GET,
                entity,
                new ParameterizedTypeReference<>() {}
        );

        Optional<String> primaryEmail = response.getBody().stream()
                .filter(emailEntry -> Boolean.TRUE.equals(emailEntry.get("primary")))
                .map(emailEntry -> (String) emailEntry.get("email"))
                .findFirst();
        primaryEmail.ifPresent(email -> attributes.put("email", email));
        if (!primaryEmail.isPresent()) {
            throw new OAuth2AuthenticationException("No primary email found in GitHub response");
        }
        System.out.println("Primary email from GitHub: " + primaryEmail.get());
    }
}