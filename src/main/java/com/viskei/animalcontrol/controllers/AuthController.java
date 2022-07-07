package com.viskei.animalcontrol.controllers;

import com.viskei.animalcontrol.payload.request.LoginRequest;
import com.viskei.animalcontrol.payload.request.SignupRequest;
import com.viskei.animalcontrol.payload.response.MessageResponse;
import com.viskei.animalcontrol.repository.UserRepository;
import com.viskei.animalcontrol.security.jwt.JwtUtils;
import com.viskei.animalcontrol.service.AuthService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;

    private final AuthService authService;

    @Autowired
    public AuthController(UserRepository userRepository,
                          JwtUtils jwtUtils,
                          AuthService authService) {
        this.userRepository = userRepository;
        this.jwtUtils = jwtUtils;
        this.authService = authService;
    }

    @PostMapping("/signin")
    @PreAuthorize("isAnonymous()")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {

        if (!userRepository.existsByUsername(loginRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is not found!"));
        }

        return authService.authenticateUser(loginRequest.getUsername(), loginRequest.getPassword());
    }

    @PostMapping("/signup")
    @PreAuthorize("isAnonymous()")
    public ResponseEntity<?> registerAndAuthenticateUser(@Valid @RequestBody SignupRequest signUpRequest) {
        if (userRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already in use!"));
        }

        authService.registerUser(signUpRequest);

        return authService.authenticateUser(signUpRequest.getUsername(), signUpRequest.getPassword());
    }

    @PostMapping("/signout")
    public ResponseEntity<?> logoutUser() {
        ResponseCookie cookie = jwtUtils.getCleanJwtCookie();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, cookie.toString())
                .body(new MessageResponse("You've been signed out!"));
    }
}
