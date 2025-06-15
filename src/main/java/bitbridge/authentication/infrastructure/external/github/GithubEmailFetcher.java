package bitbridge.authentication.infrastructure.external.github;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.*;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class GithubEmailFetcher {

    private final RestTemplate restTemplate;

    @Value("${app.github.api.email.base-url:https://api.github.com/user/emails}")
    private String githubApiBaseUrl;

    public void enrichWithPrimaryEmail(OAuth2UserRequest userRequest, Map<String, Object> attributes) {
        String token = userRequest.getAccessToken().getTokenValue();

        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        ResponseEntity<List<Map<String, Object>>> response = restTemplate.exchange(
                githubApiBaseUrl,
                HttpMethod.GET,
                entity,
                new ParameterizedTypeReference<>() {}
        );

        Optional<String> primaryEmail = response.getBody().stream()
                .filter(emailEntry -> Boolean.TRUE.equals(emailEntry.get("primary")))
                .map(emailEntry -> (String) emailEntry.get("email"))
                .findFirst();

        if (primaryEmail.isEmpty()) {
            throw new OAuth2AuthenticationException("No primary email found in GitHub response");
        }

        attributes.put("email", primaryEmail.get());
        log.info("Primary email from GitHub: {}", primaryEmail.get());
    }
}