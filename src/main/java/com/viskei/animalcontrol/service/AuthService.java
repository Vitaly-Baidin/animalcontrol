package com.viskei.animalcontrol.service;

import com.viskei.animalcontrol.payload.request.LoginRequest;
import com.viskei.animalcontrol.payload.request.SignupRequest;
import com.viskei.animalcontrol.security.services.UserDetailsImpl;

public interface AuthService {
    UserDetailsImpl authenticateUser(LoginRequest loginRequest);

    void registerUser(SignupRequest signUpRequest);
}
