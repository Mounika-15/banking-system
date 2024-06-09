package com.learning.bankingsystem.controller;

import com.learning.bankingsystem.dto.JwtAuthResponseDto;
import com.learning.bankingsystem.dto.LoginDto;
import com.learning.bankingsystem.dto.OpenAccountDto;
import com.learning.bankingsystem.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/api/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/login")
    public String showLoginForm(Model model) {
        model.addAttribute("loginDto", new LoginDto());
        return "login";
    }

    @PostMapping("/login")
    public ResponseEntity<JwtAuthResponseDto> login(@RequestBody LoginDto loginDto) {
        return new ResponseEntity<>(userService.login(loginDto), HttpStatus.OK);
    }

    @GetMapping("/register")
    public String showRegisterForm(Model model) {
        model.addAttribute("openAccountDto", new OpenAccountDto());
        return "register";
    }

    @PostMapping("/register")
    public ResponseEntity<Void> register(@RequestBody OpenAccountDto openAccountDto) {
        userService.openAccount(openAccountDto);
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
