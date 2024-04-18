package com.myprojects.jwtimplementation.controller;


import com.myprojects.jwtimplementation.exception.AuthenticationnCustomException;
import com.myprojects.jwtimplementation.jwt.JwtAuthResponse;
import com.myprojects.jwtimplementation.jwt.LoginDto;
import com.myprojects.jwtimplementation.jwt.RegisterDto;
import com.myprojects.jwtimplementation.service.AuthService;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@AllArgsConstructor
@NoArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class AuthController {


    @Autowired
    AuthService authService;

    // Build Register REST API
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody RegisterDto registerDto, @RequestParam String passwordForAdmin) throws AuthenticationnCustomException, AuthenticationnCustomException {
        String response = authService.register(registerDto, passwordForAdmin);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }

    // Build Login REST API
    @PostMapping("/login")
    public ResponseEntity<JwtAuthResponse> login(@RequestBody LoginDto loginDto){
        String token = authService.login(loginDto);

        JwtAuthResponse jwtAuthResponse = new JwtAuthResponse();
        jwtAuthResponse.setAccessToken(token);

        return new ResponseEntity<>(jwtAuthResponse, HttpStatus.OK);
    }

}

