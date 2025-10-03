package bitbridge.authentication.application.service;

import bitbridge.authentication.domain.model.User;
import bitbridge.authentication.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsImpl implements UserDetailsService {
    private UserRepository userRepository;

    @Value("${app.default.role.prefix}")
    private String defaultRolePrefix;

    @Autowired
    public CustomUserDetailsImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findByEmail(username);
        if(user.isEmpty()){
            throw new UsernameNotFoundException("User not found with email: " + username);
        }
        List<GrantedAuthority> authorityList = user.get().getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(defaultRolePrefix + role))
                .collect(Collectors.toList());
        return new org.springframework.security.core.userdetails.User(
                user.get().getEmail(),
                user.get().getPassword(),
                authorityList
        );
    }
}
