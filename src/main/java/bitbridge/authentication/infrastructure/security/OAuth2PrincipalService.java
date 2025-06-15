package bitbridge.authentication.infrastructure.security;


import bitbridge.authentication.application.service.UserService;
import bitbridge.authentication.domain.model.User;
import bitbridge.authentication.infrastructure.external.github.GithubEmailFetcher;
import bitbridge.authentication.infrastructure.security.principal.OAuth2UserPrincipal;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class OAuth2PrincipalService extends DefaultOAuth2UserService {

    private final UserService userService;
    private final GithubEmailFetcher githubEmailFetcher;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        try {
            Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());

            String provider = userRequest.getClientRegistration().getRegistrationId();

            if ("github".equals(provider)) {
                githubEmailFetcher.enrichWithPrimaryEmail(userRequest, attributes);
            }

            User user = userService.processOAuth2User(userRequest, attributes);
            return new OAuth2UserPrincipal(user, attributes);

        } catch (OAuth2AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new OAuth2AuthenticationException("OAuth2 user processing failed");
        }
    }
}