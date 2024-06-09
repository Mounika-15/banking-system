package com.learning.bankingsystem.service;

import com.learning.bankingsystem.dto.JwtAuthResponseDto;
import com.learning.bankingsystem.dto.LoginDto;
import com.learning.bankingsystem.dto.OpenAccountDto;

public interface UserService {
    JwtAuthResponseDto login(LoginDto loginDto);

    void openAccount(OpenAccountDto openAccountDto);
}
