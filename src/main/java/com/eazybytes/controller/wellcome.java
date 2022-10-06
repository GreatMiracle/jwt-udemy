package com.eazybytes.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class wellcome {
    @GetMapping("/wellcome")
    public String sayWelcome() {
        return "Welcome from Spring Application with Security";
    }
}
