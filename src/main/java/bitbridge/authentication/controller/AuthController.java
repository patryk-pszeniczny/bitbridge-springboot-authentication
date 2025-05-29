package bitbridge.authentication.controller;

import bitbridge.authentication.model.User;
import bitbridge.authentication.request.LoginRequest;
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
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
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
        String jwt = jwtService.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        return ResponseEntity.ok(new AuthResponse(
                jwt,
                "Bearer",
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }

    @GetMapping("/me")
    public ResponseEntity<?> getCurrentUser(HttpServletRequest request) {
        System.out.println("Fetching current user details...");
        String token = jwtService.parseJwt(request);
        System.out.println("Token: " + token);
        if (token != null && jwtService.validateJwtToken(token)) {
            String username = jwtService.getUserNameFromJwtToken(token);
            System.out.println("Username from token: " + username);
            User user = userService.findByUsername(username)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            return ResponseEntity.ok(user);
        }
        return ResponseEntity.badRequest().body("Invalid token");
    }

    @GetMapping("/oauth2/success")
    public ResponseEntity<?> oauth2Success(Authentication authentication) {
        String jwt = jwtService.generateJwtToken(authentication);

        UserDetailsImpl userDetails = (UserDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());
        System.out.println("OAuth2 Success: " + userDetails.getUsername() + ", Roles: " + roles);
        // Redirect to the frontend with the JWT token
        System.out.println("Generated JWT: " + jwt);
        return ResponseEntity.ok(new AuthResponse(
                jwt,
                "Bearer",
                userDetails.getUsername(),
                userDetails.getEmail(),
                roles));
    }
}