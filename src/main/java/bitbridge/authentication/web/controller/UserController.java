package bitbridge.authentication.web.controller;

import bitbridge.authentication.application.service.UserService;
import bitbridge.authentication.domain.model.User;
import bitbridge.authentication.exception.UserNotFoundException;
import bitbridge.authentication.infrastructure.security.JwtService;
import bitbridge.authentication.web.dto.response.UserResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final JwtService jwtService;
    private final UserService userService;

    @GetMapping("/profile")
    public ResponseEntity<UserResponse> getCurrentUser(@RequestHeader("Authorization") String jwt) {
        String email = jwtService.extractAndValidateToken(jwt);
        User user = userService.findByEmail(email).orElseThrow(() -> new UserNotFoundException("User not found with email: " + email));
        UserResponse userResponse = new UserResponse();
        userResponse.setEmail(user.getEmail());
        userResponse.setRoles(user.getRoles().stream().toList());
        userResponse.setUsername(user.getUsername());
        userResponse.setFirstName(user.getFirstName());
        userResponse.setLastName(user.getLastName());
        userResponse.setMessage("User profile retrieved successfully");
        return ResponseEntity.ok(userResponse);
    }
}
