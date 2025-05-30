package bitbridge.authentication.controller;

import bitbridge.authentication.model.User;
import bitbridge.authentication.request.LoginRequest;
import bitbridge.authentication.request.RegisterRequest;
import bitbridge.authentication.response.AuthResponse;
import bitbridge.authentication.service.JwtService;
import bitbridge.authentication.service.UserDetailsImpl;
import bitbridge.authentication.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserService userService;

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        System.out.println("Authenticating user: " + loginRequest.getUsername());
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        Set<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toSet());
        String jwt = jwtService.generateJwtToken(authentication);

        return ResponseEntity.ok(new AuthResponse(
                jwt,
                "Bearer",
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        System.out.println("Registering user: " + registerRequest.getUsername());
        String username = registerRequest.getUsername();
        String email = registerRequest.getEmail();

        User isUserExists = userService.findByUserNameOrEmail(username, email).orElse(null);
        if (isUserExists != null) {
            return ResponseEntity.badRequest().body("User already exists with this email");
        }
        String password = registerRequest.getPassword();
        User created = this.userService.proccessAuthUser(username, email, password);
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                        email,
                        password);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        String jwt = jwtService.generateJwtToken(authentication);
        return ResponseEntity.ok(new AuthResponse(
                jwt,
                "Bearer",
                username,
                email,
                created.getRoles()));
    }
    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
        String token = jwtService.parseJwt(request);
        if (token != null && jwtService.validateJwtToken(token)) {
            String username = jwtService.getUserNameFromJwtToken(token);
            User user = userService.findByUsername(username).orElseThrow(() -> new RuntimeException("User not found"));
            return ResponseEntity.ok(user);
        }
        return ResponseEntity.badRequest().body("Invalid token");
    }

    @GetMapping("/oauth2/success")
    public ResponseEntity<?> oauth2Success(Authentication authentication) {
        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        Set<String> roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toSet());
        return ResponseEntity.ok(new AuthResponse(
                jwtService.generateJwtToken(authentication),
                "Bearer",
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }
}