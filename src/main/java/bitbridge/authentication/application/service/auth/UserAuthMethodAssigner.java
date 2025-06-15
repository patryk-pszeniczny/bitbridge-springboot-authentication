package bitbridge.authentication.application.service.auth;

import bitbridge.authentication.domain.model.User;
import bitbridge.authentication.domain.model.UserAuthMethod;
import bitbridge.authentication.domain.valueobject.AuthProvider;
import org.springframework.stereotype.Component;

@Component
public class UserAuthMethodAssigner {

    public void assign(User user, AuthProvider provider, String providerId) {
        UserAuthMethod method = new UserAuthMethod();
        method.setProvider(provider);
        method.setProviderId(providerId);
        method.setUser(user);
        user.getAuthMethods().add(method);
    }
}