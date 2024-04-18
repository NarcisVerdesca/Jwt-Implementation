package com.myprojects.jwtimplementation.service;


import com.myprojects.jwtimplementation.exception.AuthenticationnCustomException;
import com.myprojects.jwtimplementation.jwt.LoginDto;
import com.myprojects.jwtimplementation.jwt.RegisterDto;

public interface AuthService {
    String login(LoginDto loginDto);

    String register(RegisterDto registerDto, String paswordForAdmin) throws AuthenticationnCustomException;
}
