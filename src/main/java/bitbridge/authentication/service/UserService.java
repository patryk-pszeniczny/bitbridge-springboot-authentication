package bitbridge.authentication.service;

import bitbridge.authentication.model.AuthMethod;
import bitbridge.authentication.model.AuthProviderEnum;
import bitbridge.authentication.model.User;
import bitbridge.authentication.repository.AuthMethodRepository;
import bitbridge.authentication.repository.UserRepository;
import jakarta.validation.constraints.NotBlank;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final AuthMethodRepository authMethodRepository;
    private final Keycloak keycloakAdmin;

    @Transactional
    public User proccessAuthUser(String username, String email, String password) {
        try {
            User user = registerNewUser(Map.of(
                    "name", username,
                    "email", email,
                    "password", password
            ));
            addAuthMethod(user, AuthProviderEnum.LOCAL, null);
            return user;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }
    @Transactional
    public User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User, Map<String, Object> attributes) {
        try {
            String provider = oAuth2UserRequest.getClientRegistration().getRegistrationId();
            AuthProviderEnum authProvider;
            try {
                authProvider = AuthProviderEnum.valueOf(provider.toUpperCase());
            } catch (IllegalArgumentException e) {
                throw new OAuth2AuthenticationException("Unsupported provider: " + provider);
            }
            Optional<String> providerId = Optional.ofNullable(
                    (attributes.get("sub") != null ?
                            attributes.get("sub") :
                            attributes.get("id")).toString()
            );
            if(providerId.isEmpty()) {
                throw new OAuth2AuthenticationException("Provider ID not found in user attributes");
            }
            Optional<User> userOptionalProvider = authMethodRepository.findUserByProviderAndProviderId(authProvider, providerId.get());
            if (userOptionalProvider.isPresent()) {
                return userOptionalProvider.get();
            }
            Optional<User> userOptionalEmail = userRepository.findByEmail(attributes.get("email").toString());
            if(userOptionalEmail.isPresent()) {
                User user = userOptionalEmail.get();
                addAuthMethod(user, authProvider, providerId.get());
                return userRepository.save(user);
            }
            User user = registerNewUser(attributes);
            addAuthMethod(user, authProvider, providerId.get());
            return user;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private User registerNewUser(Map<String, Object> attributes) {
        User user = new User();
        String email = attributes.get("email").toString();
        System.out.println(attributes);
        String name = attributes.containsKey("name") ? attributes.get("name").toString() : email;
        System.out.println("Registering new user: " + name + ", email: " + email);
        String password = attributes.containsKey("password") ? attributes.get("password").toString() : null;
        if (name != null && name.contains(" ")) {
            String[] nameParts = name.split(" ");
            user.setFirstName(nameParts[0]);
            if (nameParts.length > 1) {
                user.setLastName(nameParts[1]);
            }
        }
        user.setPassword(password);
        user.setEmail(email);
        user.setUsername(name);
        user.setRoles(Set.of("USER"));
        return userRepository.save(user);
    }

    public void addAuthMethod(User user, AuthProviderEnum provider, String providerId) {
        AuthMethod method = new AuthMethod();
        method.setProvider(provider);
        method.setProviderId(providerId);
        method.setUser(user);
        user.getAuthMethods().add(method);
    }
    private void registerUserInKeycloak(User user) {
        UserRepresentation keycloakUser = new UserRepresentation();
        keycloakUser.setUsername(user.getUsername());
        keycloakUser.setEmail(user.getEmail());
        keycloakUser.setFirstName(user.getFirstName());
        keycloakUser.setLastName(user.getLastName());
        keycloakUser.setEnabled(true);

        keycloakAdmin.realm("social-login-demo").users().create(keycloakUser);
    }

    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    @Transactional(readOnly = true)
    public Optional<User> findByUserNameOrEmail(@NotBlank String userName, @NotBlank String email) {
        return userRepository.findByUsernameOrEmail(userName, email);
    }
    @Transactional(readOnly = true)
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}