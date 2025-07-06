package com.domain.authentication.config;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import com.domain.authentication.entity.User;
import com.domain.authentication.repository.UserRepository;
import com.domain.authentication.util.JwtUtil;

@Configuration
public class SecurityConfig {
	
	public SecurityConfig(UserRepository userRepository,JwtUtil jwtUtil)
	{
		this.userRepository = userRepository;
		this.jwtUtil = jwtUtil;
	}
	
	
    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .cors(cors -> cors.configurationSource(request -> {
                var corsConfig = new org.springframework.web.cors.CorsConfiguration();
                corsConfig.setAllowedOrigins(List.of("http://localhost:4200"));
                corsConfig.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
                corsConfig.setAllowedHeaders(List.of("*"));
                corsConfig.setAllowCredentials(true);
                return corsConfig;
            }))
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/", "/login/**", "/oauth2/**","/signup").permitAll()
                    .anyRequest().authenticated()
                ) .oauth2Login(oauth2 -> oauth2
                	    .successHandler(oAuth2SuccessHandler())
                		)

            .csrf(csrf -> csrf.disable());
        return http.build();
    }
    @Bean
    public AuthenticationSuccessHandler oAuth2SuccessHandler() {
        return (request, response, authentication) -> {

            OAuth2User oAuth2User = (OAuth2User) authentication.getPrincipal();
            Map<String, Object> attributes = oAuth2User.getAttributes();

            String email = (String) attributes.get("email");
            String name = (String) attributes.get("name");

            // Check if user exists, else register
            User user = userRepository.findByEmail(email).orElseGet(() -> {
                User newUser = new User();
                newUser.setEmail(email);
                newUser.setName(name);
                newUser.setProvider("GOOGLE");
                newUser.setCreatedAt(LocalDateTime.now());
                return userRepository.save(newUser);
            });

            // Generate JWT token
            String token = jwtUtil.generateToken(email);

            // Redirect with token as query param to frontend
            String redirectUrl = String.format("http://localhost:4200/oauth-success?token=%s&username=%s&email=%s&createdAt=%s",
                    token,
                    URLEncoder.encode(user.getName(), StandardCharsets.UTF_8),
                    URLEncoder.encode(user.getEmail(), StandardCharsets.UTF_8),
                    URLEncoder.encode(user.getCreatedAt().toString(), StandardCharsets.UTF_8));

            response.sendRedirect(redirectUrl);
        };
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}