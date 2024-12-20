package kz.zhelezyaka.securitydemo.controllers;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/test")
    public String testMapping() {
        return "This is a test mapping";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/user")
    public String userEndpoint() {
        return "Hello User";
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint() {
        return "Hello admin";
    }
}
