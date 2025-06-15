package bitbridge.authentication.web.controller;

import bitbridge.authentication.application.service.UserService;
import bitbridge.authentication.domain.model.User;
import bitbridge.authentication.domain.model.UserAuthMethod;
import bitbridge.authentication.domain.repository.UserAuthMethodRepository;
import bitbridge.authentication.exception.UserNotFoundException;
import bitbridge.authentication.infrastructure.security.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/provider")
@RequiredArgsConstructor
public class ProviderController {

    private final UserService userService;
    private final JwtService jwtService;
    private final UserAuthMethodRepository userAuthMethodRepository;
    @GetMapping("/user")
    public ResponseEntity<List<UserAuthMethod>> userProviders(
            @RequestHeader("Authorization") String jwt) {
        String email = jwtService.extractAndValidateToken(jwt);
        User user = userService.findByEmail(email).orElseThrow(() ->
                new UserNotFoundException("User not found with email: " + email));

        List<UserAuthMethod> authMethods = userAuthMethodRepository.findAllByUserId(user.getId())
                        .orElseThrow(() -> new UserNotFoundException("No providers found for user with ID: " + user.getId()));

        return ResponseEntity.ok(authMethods);
    }
}
