package com.example.sanchecktest.controller;

import com.example.sanchecktest.dto.AddUserDTO;
import com.example.sanchecktest.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;

@RequiredArgsConstructor
@Controller
public class UserController {

    private final UserService userService;

    @PostMapping("/user")
    public String signUp(AddUserDTO adduser) {

        userService.save(adduser);
        return "redirect:/login";
    }
}
