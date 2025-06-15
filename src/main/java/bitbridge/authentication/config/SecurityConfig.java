package bitbridge.authentication.config;

import bitbridge.authentication.config.handler.JwtOAuth2FailureHandler;
import bitbridge.authentication.config.handler.JwtOAuth2SuccessHandler;
import bitbridge.authentication.config.policy.CorsPolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    @Value("${app.oauth2.login-page:http://localhost:5173}")
    private String oauth2LoginPage;

    @Value("${app.oauth2.user-request-matchers}")
    private String[] requestUserMatchers;

    @Value("${app.oauth2.admin-request-matchers}")
    private String[] requestAdminMatchers;

    @Value("${app.default.admin.role}")
    private String defaultAdminRole;

    @Value("${app.oauth2.authorization-endpoint}")
    private String authorizationEndpoint;

    @Value("${app.oauth2.redirection-endpoint}")
    private String redirectionEndpoint;


    private final CorsPolicy corsPolicy;
    private final JwtOAuth2SuccessHandler successHandler;
    private final JwtOAuth2FailureHandler failureHandler;

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        return corsPolicy.createCorsConfigurationSource();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(authz -> authz
                        .requestMatchers(requestUserMatchers)
                            .permitAll()
                        .requestMatchers(requestAdminMatchers)
                            .hasRole(defaultAdminRole)
                        .anyRequest().authenticated()
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .oauth2Login(oauth2 -> oauth2
                        .loginPage(oauth2LoginPage)
                        .authorizationEndpoint(endp -> endp.baseUri(authorizationEndpoint))
                        .redirectionEndpoint(endp -> endp.baseUri(redirectionEndpoint))
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                );
        return http.build();
    }
}