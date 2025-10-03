package bitbridge.authentication.web.controller;

import bitbridge.authentication.application.service.CustomUserDetailsImpl;
import bitbridge.authentication.application.service.UserService;
import bitbridge.authentication.domain.model.User;
import bitbridge.authentication.infrastructure.security.JwtService;
import bitbridge.authentication.infrastructure.security.UserPrincipal;
import bitbridge.authentication.web.dto.request.LoginRequest;
import bitbridge.authentication.web.dto.request.RegisterRequest;
import bitbridge.authentication.web.dto.response.LoginResponse;
import bitbridge.authentication.web.dto.response.RegisterResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final JwtService jwtService;
    private final UserService userService;
    private final CustomUserDetailsImpl userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest loginRequest) {
        String email = loginRequest.getEmail();
        String password = loginRequest.getPassword();

        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(email);
        } catch (bitbridge.authentication.exception.UserNotFoundException e) {
            return unauthorized("Invalid email or password");
        }

        if (!passwordEncoder.matches(password, userDetails.getPassword())) {
            return unauthorized("Invalid email or password");
        }

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails, null, userDetails.getAuthorities()
        );
        String token = jwtService.generateJwtToken(authentication);

        LoginResponse response = new LoginResponse();
        response.setEmail(email);
        response.setRoles(userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList());
        response.setAccessToken(token);
        response.setMessage("Login successful");

        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> register(@Valid @RequestBody RegisterRequest request) {
        System.out.println("Register request received: " + request);
        if (userService.findByUserNameOrEmail(request.getUsername(), request.getEmail()).isPresent()) {
            RegisterResponse response = new RegisterResponse();
            response.setMessage("User already exists with given username or email");
            return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        }

        User user = userService.proccessAuthUser(
                request.getUsername(),
                request.getEmail(),
                request.getPassword()
        );

        Authentication authentication = new UsernamePasswordAuthenticationToken(
                user.getEmail(), null, user.getRoles().stream()
                .map(role -> (GrantedAuthority) () -> "ROLE_" + role)
                .toList()
        );

        String token = jwtService.generateJwtToken(authentication);

        RegisterResponse response = new RegisterResponse();
        response.setEmail(user.getEmail());
        response.setRoles(user.getRoles().stream().toList());
        response.setAccessToken(token);
        response.setMessage("User registered successfully");

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    @GetMapping("/oauth2/success")
    public ResponseEntity<LoginResponse> oauth2Success(Authentication authentication) {
        UserPrincipal userDetails = (UserPrincipal) authentication.getPrincipal();
        String token = jwtService.generateJwtToken(authentication);

        LoginResponse response = new LoginResponse();
        response.setEmail(userDetails.getEmail());
        response.setRoles(userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList());
        response.setAccessToken(token);
        response.setMessage("OAuth2 login successful");

        return ResponseEntity.ok(response);
    }

    private ResponseEntity<LoginResponse> unauthorized(String message) {
        LoginResponse response = new LoginResponse();
        response.setMessage(message);
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }
}
