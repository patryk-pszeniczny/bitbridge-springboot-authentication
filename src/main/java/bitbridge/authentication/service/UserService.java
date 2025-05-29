package bitbridge.authentication.service;

import bitbridge.authentication.model.User;
import bitbridge.authentication.repository.UserRepository;
import lombok.RequiredArgsConstructor;
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
public class UserService {

    private final UserRepository userRepository;
    private final Keycloak keycloakAdmin;

    @Transactional
    public User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User, Map<String, Object> attributes) {
        try {
            String provider = oAuth2UserRequest.getClientRegistration().getRegistrationId();
            User.AuthProvider authProvider;
            try {
                authProvider = User.AuthProvider.valueOf(provider.toUpperCase());
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
            Optional<User> userOptional = userRepository.findByProviderAndProviderId(authProvider, providerId.get());
            System.out.println(userOptional);
            if (userOptional.isPresent()) {
                return userOptional.get();
            }
            User user = registerNewUser(oAuth2User, authProvider, providerId, attributes);
            System.out.println("User registered: " + user.getUsername());
            System.out.println("Id: " + user.getId());
            System.out.println("Email: " + user.getEmail());
            System.out.println("First Name: " + user.getFirstName());
            System.out.println("Last Name: " + user.getLastName());
            System.out.println("Provider: " + user.getProvider());
            System.out.println("Provider ID: " + user.getProviderId());
            System.out.println("Username: " + user.getUsername());
            System.out.println("Roles: " + user.getRoles());

            return user;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private User registerNewUser(OAuth2User oAuth2User,
                                 User.AuthProvider provider,
                                 Optional<String> providerId,
                                 Map<String, Object> attributes) {
        User user = new User();
        user.setProvider(provider);
        user.setProviderId(providerId.orElse("unknown"));

        String email = attributes.get("email").toString();
        String name = attributes.containsKey("name")?attributes.get("name").toString():"unknown";

        if (name != null) {
            String[] nameParts = name.split(" ");
            user.setFirstName(nameParts[0]);
            if (nameParts.length > 1) {
                user.setLastName(nameParts[1]);
            }
        }

        user.setEmail(email);
        user.setUsername(email);
        user.setRoles(Set.of("USER"));
        try {
            return userRepository.save(user);
        }catch (Exception e) {
            throw new InternalAuthenticationServiceException("Error registering user in Keycloak: " + e.getMessage(), e);
        }
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
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }
}