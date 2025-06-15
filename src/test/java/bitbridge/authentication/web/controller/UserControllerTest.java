package bitbridge.authentication.web.controller;

import bitbridge.authentication.application.service.UserService;
import bitbridge.authentication.domain.model.User;
import bitbridge.authentication.infrastructure.security.JwtService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(UserController.class)
@AutoConfigureMockMvc(addFilters = false)
public class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtService jwtService;

    @MockBean
    private UserService userService;

    @Test
    void shouldReturnUserDataWhenTokenIsValid() throws Exception {
        // given
        String token = "Bearer valid.jwt.token";
        String email = "user@example.com";

        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail(email);
        user.setUsername("testuser");
        user.setRoles(Set.of("USER"));

        // when
        when(jwtService.extractAndValidateToken(anyString())).thenReturn(email);
        when(userService.findByEmail(email)).thenReturn(Optional.of(user));

        // then
        mockMvc.perform(get("/api/user/profile")
                        .header("Authorization", token)
                        .accept(MediaType.APPLICATION_JSON))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(email))
                .andExpect(jsonPath("$.username").value("testuser"));
    }

    @Test
    void shouldReturn404WhenUserNotFound() throws Exception {
        when(jwtService.extractAndValidateToken(anyString())).thenReturn("missing@example.com");
        when(userService.findByEmail("missing@example.com")).thenReturn(Optional.empty());

        mockMvc.perform(get("/api/user/profile")
                        .header("Authorization", "Bearer invalid.token"))
                .andExpect(status().isInternalServerError());
    }
}
