package bitbridge.authentication.application.service;

import bitbridge.authentication.application.service.factory.UserRegistrationFactory;
import bitbridge.authentication.domain.model.User;
import bitbridge.authentication.domain.repository.UserAuthMethodRepository;
import bitbridge.authentication.domain.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.when;

class UserServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private UserAuthMethodRepository authMethodRepository;
    @Mock private PasswordEncoder passwordEncoder;
    @Mock private UserRegistrationFactory registrationFactory;
    @InjectMocks private UserAuthenticationService userService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void shouldCreateNewUserWithLocalAuth() {
        String username = "Anna";
        String email = "anna@example.com";
        String rawPassword = "haslo123";
        String encodedPassword = "encodedPassword";

        User dummyUser = new User();
        dummyUser.setEmail(email);
        dummyUser.setUsername(username);
        dummyUser.setPassword(encodedPassword);
        dummyUser.setRoles(Set.of("USER"));

        when(passwordEncoder.encode(rawPassword)).thenReturn(encodedPassword);
        when(registrationFactory.createFromCredentials(username, email, rawPassword, passwordEncoder))
                .thenReturn(dummyUser);
        when(userRepository.save(any(User.class))).thenAnswer(i -> i.getArgument(0));

        // when
        User result = userService.proccessAuthUser(username, email, rawPassword);

        // then
        assertEquals(email, result.getEmail());
        assertEquals(username, result.getUsername());
        assertEquals(encodedPassword, result.getPassword());
        assertTrue(result.getRoles().contains("USER"));
    }
}
