package kz.zhelezyaka.securitydemo.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @GetMapping("/test")
    public String testMapping() {
        return "This is a test mapping";
    }
}
