package com.viskei.animalcontrol.service;

import com.viskei.animalcontrol.payload.request.SignupRequest;
import org.springframework.http.ResponseEntity;

public interface AuthService {
    ResponseEntity<?> authenticateUser(String username, String password);

    void registerUser(SignupRequest signUpRequest);
}
