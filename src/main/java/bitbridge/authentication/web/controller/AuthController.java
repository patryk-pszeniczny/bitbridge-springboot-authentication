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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    private final JwtService jwtService;
    private final UserService userService;
    private final CustomUserDetailsImpl customUserDetailsService;
    private final PasswordEncoder passwordEncoder;
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        System.out.println("Login request received: " + loginRequest);
        String email = loginRequest.getEmail();
        String password = loginRequest.getPassword();
        UserDetails userDetails = customUserDetailsService.loadUserByUsername(email);
        if (userDetails == null) {
            LoginResponse loginResponse = new LoginResponse();
            loginResponse.setMessage("Invalid user");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(loginResponse);
        }
        if(!passwordEncoder.matches(password, userDetails.getPassword())) {
            LoginResponse loginResponse = new LoginResponse();
            loginResponse.setMessage("Invalid username or password");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(loginResponse);
        }
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtService.generateJwtToken(authentication);
        List<String> roles = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setAccessToken(jwt);
        loginResponse.setEmail(email);
        loginResponse.setRoles(roles);
        loginResponse.setMessage("Login successful");
        return ResponseEntity.ok(loginResponse);
    }
    @PostMapping("/register")
    public ResponseEntity<RegisterResponse> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        String username = registerRequest.getUsername();
        String email = registerRequest.getEmail();
        User isUserExists = userService.findByUserNameOrEmail(username, email).orElse(null);
        if (isUserExists != null) {
            RegisterResponse registerResponse = new RegisterResponse();
            registerResponse.setMessage("User already exists with username or email");
            return ResponseEntity.badRequest().body(registerResponse);
        }

        String password = registerRequest.getPassword();

        Authentication authentication = new UsernamePasswordAuthenticationToken(email, password);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        User user = this.userService.proccessAuthUser(username, email, password);

        RegisterResponse registerResponse = new RegisterResponse();
        registerResponse.setEmail(user.getEmail());
        registerResponse.setAccessToken(jwtService.generateJwtToken(authentication));
        registerResponse.setRoles(user.getRoles().stream().toList());
        registerResponse.setMessage("User registered successfully");
        return ResponseEntity.status(HttpStatus.CREATED).body(registerResponse);
    }
    @GetMapping("/oauth2/success")
    public ResponseEntity<?> oauth2Success(Authentication authentication) {
        UserPrincipal userDetails = (UserPrincipal) authentication.getPrincipal();
        Set<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        String jwtToken = jwtService.generateJwtToken(authentication);

        LoginResponse loginResponse = new LoginResponse();
        loginResponse.setAccessToken(jwtToken);
        loginResponse.setEmail(userDetails.getUsername());
        loginResponse.setRoles(roles.stream().toList());
        loginResponse.setMessage("OAuth2 login successful");
        return ResponseEntity.ok(loginResponse);
    }
}