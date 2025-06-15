package bitbridge.authentication.application.service;

import bitbridge.authentication.application.service.auth.UserAuthMethodAssigner;
import bitbridge.authentication.application.service.factory.UserRegistrationFactory;
import bitbridge.authentication.domain.model.User;
import bitbridge.authentication.domain.repository.UserAuthMethodRepository;
import bitbridge.authentication.domain.repository.UserRepository;
import bitbridge.authentication.domain.valueobject.AuthProvider;
import bitbridge.authentication.infrastructure.external.keycloak.ExternalUserRegistrationClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserAuthenticationService implements UserService {

    private final UserRepository userRepository;
    private final UserAuthMethodRepository authMethodRepository;
    private final UserRegistrationFactory registrationFactory;
    private final UserAuthMethodAssigner authMethodAssigner;
    private final ExternalUserRegistrationClient keycloakClient;
    private final PasswordEncoder passwordEncoder;
    private final UserAuthMethodRepository userAuthMethodRepository;

    @Override
    @Transactional
    public User proccessAuthUser(String username, String email, String password) {
        User user = registrationFactory.createFromCredentials(username, email, password, passwordEncoder);
        authMethodAssigner.assign(user, AuthProvider.LOCAL, null);
        return userRepository.save(user);
    }
    @Transactional
    public User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, Map<String, Object> attributes) {
        String providerId = Optional.ofNullable(attributes.get("sub") != null
                        ? attributes.get("sub") : attributes.get("id"))
                .map(Object::toString)
                .orElseThrow(() -> new OAuth2AuthenticationException("Provider ID not found"));

        AuthProvider provider = AuthProvider.valueOf(
                oAuth2UserRequest.getClientRegistration().getRegistrationId().toUpperCase()
        );
        return authMethodRepository.findUserByProviderAndProviderId(provider, providerId)
                .or(() -> userRepository.findByEmail(attributes.get("email").toString())
                        .map(user -> {
                            authMethodAssigner.assign(user, provider, providerId);
                            return userRepository.save(user);
                        }))
                .orElseGet(() -> {
                    User user = registrationFactory.createFromOAuth(attributes);
                    authMethodAssigner.assign(user, provider, providerId);
                    return userRepository.save(user);
                });
    }

    @Override
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Override
    public Optional<User> findByUserNameOrEmail(String username, String email) {
        return userRepository.findByUsernameOrEmail(username, email);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

}