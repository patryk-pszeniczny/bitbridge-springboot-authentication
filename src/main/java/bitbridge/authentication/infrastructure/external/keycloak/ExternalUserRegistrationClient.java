package bitbridge.authentication.infrastructure.external.keycloak;

import bitbridge.authentication.domain.model.User;
import lombok.RequiredArgsConstructor;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class ExternalUserRegistrationClient {

    private final Keycloak keycloak;

    public void registerInKeycloak(User user) {
        UserRepresentation kcUser = new UserRepresentation();
        kcUser.setUsername(user.getUsername());
        kcUser.setEmail(user.getEmail());
        kcUser.setFirstName(user.getFirstName());
        kcUser.setLastName(user.getLastName());
        kcUser.setEnabled(true);

        keycloak.realm("social-login-demo")
                .users()
                .create(kcUser);
    }
}