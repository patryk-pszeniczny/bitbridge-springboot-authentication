package bitbridge.authentication.web.controller;

import bitbridge.authentication.application.service.CustomUserDetailsImpl;
import bitbridge.authentication.application.service.UserService;
import bitbridge.authentication.domain.model.User;
import bitbridge.authentication.infrastructure.security.JwtService;
import bitbridge.authentication.web.dto.request.LoginRequest;
import bitbridge.authentication.web.dto.request.RegisterRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Optional;
import java.util.Set;

import static org.mockito.ArgumentMatchers.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(AuthController.class)
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private JwtService jwtService;

    @MockBean
    private UserService userService;

    @MockBean
    private CustomUserDetailsImpl customUserDetailsService;

    @MockBean
    private PasswordEncoder passwordEncoder;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void shouldReturnJwtTokenForValidLogin() throws Exception {
        LoginRequest request = new LoginRequest();
        request.setPassword("password123");
        request.setEmail("test@example.com");

        User user = new User();
        user.setEmail("test@example.com");
        user.setUsername("testuser");
        user.setPassword("encoded_password");
        user.setRoles(Set.of("USER"));

        Mockito.when(customUserDetailsService.loadUserByUsername("test@example.com"))
                .thenReturn(org.springframework.security.core.userdetails.User
                        .withUsername("test@example.com")
                        .password("encoded_password")
                        .roles("USER")
                        .build());

        Mockito.when(passwordEncoder.matches(anyString(), eq("encoded_password"))).thenReturn(true);
        Mockito.when(jwtService.generateJwtToken(any())).thenReturn("mocked-jwt");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").value("mocked-jwt"))
                .andExpect(jsonPath("$.message").value("Login successful"));
    }

    @Test
    void shouldRegisterNewUser() throws Exception {
        RegisterRequest request = new RegisterRequest("testuser", "test@example.com", "password123");

        Mockito.when(userService.findByUserNameOrEmail(any(), any())).thenReturn(Optional.empty());

        User user = new User();
        user.setUsername("testuser");
        user.setEmail("test@example.com");
        user.setRoles(Set.of("USER"));

        Mockito.when(userService.proccessAuthUser(anyString(), anyString(), anyString())).thenReturn(user);
        Mockito.when(jwtService.generateJwtToken(any())).thenReturn("new-jwt-token");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.email").value("test@example.com"))
                .andExpect(jsonPath("$.accessToken").value("new-jwt-token"))
                .andExpect(jsonPath("$.message").value("User registered successfully"));
    }
}
