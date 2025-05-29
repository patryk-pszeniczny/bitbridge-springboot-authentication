package bitbridge.authentication.service;

import bitbridge.authentication.model.User;
import bitbridge.authentication.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final Keycloak keycloakAdmin;

    @Transactional
    public User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        try {
            String provider = oAuth2UserRequest.getClientRegistration().getRegistrationId();
            User.AuthProvider authProvider = User.AuthProvider.valueOf(provider.toUpperCase());

            String providerId = oAuth2User.getAttribute("sub") != null ?
                    oAuth2User.getAttribute("sub") : oAuth2User.getAttribute("id");

            Optional<User> userOptional = userRepository.findByProviderAndProviderId(authProvider, providerId);

            if (userOptional.isPresent()) {
                return userOptional.get();
            } else {
                return registerNewUser(oAuth2UserRequest, oAuth2User, authProvider, providerId);
            }
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private User registerNewUser(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User,
                                 User.AuthProvider provider, String providerId) {
        User user = new User();
        user.setProvider(provider);
        user.setProviderId(providerId);

        String email = oAuth2User.getAttribute("email");
        String name = oAuth2User.getAttribute("name");

        if (name != null) {
            String[] nameParts = name.split(" ");
            user.setFirstName(nameParts[0]);
            if (nameParts.length > 1) {
                user.setLastName(nameParts[1]);
            }
        }

        user.setEmail(email);
        user.setUsername(email != null ? email : providerId);
        user.setRoles(Set.of("USER"));

        return userRepository.save(user);
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