package com.example.sanchecktest.controller;

import com.example.sanchecktest.dto.AddUserDTO;
import com.example.sanchecktest.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@RequiredArgsConstructor
@Controller
public class UserController {

    private final UserService userService;

    //커스텀 로그인 설정 후 매핑
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @PostMapping("/user")
    public String signUp(AddUserDTO adduser) {

        userService.save(adduser);
        return "redirect:/login";
    }

    @GetMapping("/signup")
    public String signup() {
        return "signup";
    }
}
