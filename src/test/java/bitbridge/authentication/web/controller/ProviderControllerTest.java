package bitbridge.authentication.web.controller;

import bitbridge.authentication.application.service.UserService;
import bitbridge.authentication.domain.model.User;
import bitbridge.authentication.domain.model.UserAuthMethod;
import bitbridge.authentication.domain.repository.UserAuthMethodRepository;
import bitbridge.authentication.domain.valueobject.AuthProvider;
import bitbridge.authentication.infrastructure.security.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(ProviderController.class)
@AutoConfigureMockMvc(addFilters = false)
class ProviderControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtService jwtService;

    @MockBean
    private UserService userService;

    @MockBean
    private UserAuthMethodRepository userAuthMethodRepository;

    @Test
    void shouldReturnUserAuthMethods() throws Exception {
        // given
        String jwtHeader = "Bearer valid.jwt.token";
        String email = "user@example.com";

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail(email);
        user.setUsername("exampleUser");
        user.setRoles(Set.of("USER"));

        UserAuthMethod method = new UserAuthMethod();
        method.setProviderId("12345");
        method.setProvider(AuthProvider.GOOGLE);
        method.setUser(user);

        // when
        when(jwtService.extractAndValidateToken(anyString())).thenReturn(email);
        when(userService.findByEmail(email)).thenReturn(Optional.of(user));
        when(userAuthMethodRepository.findAllByUserId(user.getId()))
                .thenReturn(Optional.of(List.of(method)));

        // then
        mockMvc.perform(get("/api/provider/user")
                        .header("Authorization", jwtHeader)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].provider").value("GOOGLE"))
                .andExpect(jsonPath("$[0].providerId").value("12345"));
    }

    @Test
    void shouldReturn404IfUserNotFound() throws Exception {
        when(jwtService.extractAndValidateToken(anyString())).thenReturn("missing@example.com");
        when(userService.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/provider/user")
                        .header("Authorization", "Bearer token"))
                .andExpect(status().isInternalServerError());
    }

    @Test
    void shouldReturn404IfNoAuthMethodsFound() throws Exception {
        String email = "no.methods@example.com";
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail(email);

        when(jwtService.extractAndValidateToken(anyString())).thenReturn(email);
        when(userService.findByEmail(email)).thenReturn(Optional.of(user));
        when(userAuthMethodRepository.findAllByUserId(user.getId()))
                .thenReturn(Optional.empty());

        mockMvc.perform(get("/api/provider/user")
                        .header("Authorization", "Bearer token"))
                .andExpect(status().isInternalServerError());
    }
}
