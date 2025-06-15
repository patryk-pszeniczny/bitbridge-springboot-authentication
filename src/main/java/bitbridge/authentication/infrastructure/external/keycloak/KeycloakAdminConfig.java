package bitbridge.authentication.infrastructure.external.keycloak;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeycloakAdminConfig {

    @Value("${KEYCLOAK_URL}")
    private String serverUrl;

    @Value("${KEYCLOAK_REALM}")
    private String realm;

    @Value("${KEYCLOAK_ADMIN_CLIENT_ID}")
    private String clientId;

    @Value("${KEYCLOAK_ADMIN_USERNAME}")
    private String username;

    @Value("${KEYCLOAK_ADMIN_PASSWORD}")
    private String password;

    @Bean
    public Keycloak keycloakAdmin() {
        return KeycloakBuilder.builder()
                .serverUrl(serverUrl)
                .realm(realm)
                .clientId(clientId)
                .username(username)
                .password(password)
                .build();
    }
}