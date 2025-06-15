package bitbridge.authentication.application.service.factory;

import bitbridge.authentication.domain.model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

@Component
public class UserRegistrationFactory {
    public User createFromCredentials(String name, String email, String password, PasswordEncoder encoder) {
        User user = buildBasicUser(name, email);
        user.setPassword(encoder.encode(password));
        return user;
    }

    public User createFromOAuth(Map<String, Object> attributes) {
        String name = attributes.getOrDefault("name", attributes.get("email")).toString();
        String email = attributes.get("email").toString();

        User user = buildBasicUser(name, email);
        user.setPassword(null);
        return user;
    }

    private User buildBasicUser(String name, String email) {
        User user = new User();
        user.setEmail(email);
        user.setUsername(name);
        user.setRoles(Set.of("USER"));

        if (name.contains(" ")) {
            String[] parts = name.split(" ");
            user.setFirstName(parts[0]);
            if (parts.length > 1) user.setLastName(parts[1]);
        }

        return user;
    }
}
