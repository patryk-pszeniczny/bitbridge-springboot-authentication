package bitbridge.authentication.application.service;

import bitbridge.authentication.domain.model.User;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;

import java.util.Map;
import java.util.Optional;


public interface UserService {

    User proccessAuthUser(String username, String email, String password);
    User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, Map<String, Object> attributes);
    Optional<User> findByUsername(String username);
    Optional<User> findByUserNameOrEmail(String userName, String email);
    Optional<User> findByEmail(String email);

}