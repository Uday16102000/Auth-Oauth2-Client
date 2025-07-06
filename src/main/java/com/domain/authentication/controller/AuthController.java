package com.domain.authentication.controller;


import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.domain.authentication.entity.User;
import com.domain.authentication.model.AuthRequest;
import com.domain.authentication.repository.UserRepository;
import com.domain.authentication.util.JwtUtil;

import lombok.RequiredArgsConstructor;

@RestController
@CrossOrigin
public class AuthController {
	
	public AuthController( UserRepository userRepository,JwtUtil jwtUtil)
	{
		this.userRepository = userRepository;
		this.passwordEncoder = new BCryptPasswordEncoder();
		this.jwtUtil = jwtUtil;
	}

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;

    @PostMapping("/signup")
    public ResponseEntity<String> signup(@RequestBody User user) {
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
        	 return ResponseEntity
        	            .status(HttpStatus.CONFLICT)
        	            .body("User already exists");        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setProvider("LOCAL");
        user.setCreatedAt(LocalDateTime.now());
        userRepository.save(user);
        return ResponseEntity.ok("User registered successfully");
    }
    
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthRequest request) {
        User existingUser = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Invalid email or password"));

        if (!passwordEncoder.matches(request.getPassword(), existingUser.getPassword())) {
            return ResponseEntity
    	            .status(HttpStatus.BAD_REQUEST)
    	            .body("Invalid email or password");   
        }

        // Generate JWT token
        String accessToken = jwtUtil.generateToken(request.getEmail());
        String refreshToken = jwtUtil.generateRefreshToken(request.getEmail());

        // Extract username from email
        String email = existingUser.getEmail();
        String username = email.contains("@") ? email.substring(0, email.indexOf("@")) : email;

        // Prepare response map
        Map<String, Object> response = new HashMap<>();
        response.put("username", username);
        response.put("email", email);
        response.put("createdAt", existingUser.getCreatedAt()); // ensure createdAt exists in User entity
        response.put("accessToken", accessToken);
        response.put("refreshToken", refreshToken);

        return ResponseEntity.ok(response);   
        }
    
    @GetMapping("/hello")
    public String hello() {
        return "Hello, authenticated user!";
    }
    
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");

        try {
            String email = jwtUtil.extractUsername(refreshToken);
            if (jwtUtil.validateToken(refreshToken, email)) {
                String newAccessToken = jwtUtil.generateToken(email);
                Map<String, String> response = new HashMap<>();
                response.put("accessToken", newAccessToken);
                return ResponseEntity.ok(response);
            }
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
        }
    }


}
