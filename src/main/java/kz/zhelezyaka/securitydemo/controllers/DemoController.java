package kz.zhelezyaka.securitydemo.controllers;

import kz.zhelezyaka.jwt.JwtUtils;
import kz.zhelezyaka.jwt.LoginRequest;
import kz.zhelezyaka.jwt.LoginResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
public class DemoController {

    private static final Logger log = LoggerFactory.getLogger(DemoController.class);
    @Autowired
    private JwtUtils jwtUtils;
    @Autowired
    private AuthenticationManager authenticationManager;

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

    @PostMapping("/signin")
    public ResponseEntity<?> authenticationUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication;
        try {
            authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
                            loginRequest.getPassword()));
        } catch (AuthenticationException exception) {
            Map<String, Object> map = new HashMap<>();
            map.put("message", "Bad credentials");
            map.put("status", false);
            return new ResponseEntity<>(map, HttpStatus.NOT_FOUND);
        }

        SecurityContextHolder
                .getContext()
                .setAuthentication(authentication);

        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String jwtToken = jwtUtils.generateTokenFromUsername(userDetails);

        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .collect(Collectors.toList());

        LoginResponse response = new LoginResponse(userDetails.getUsername(), roles, jwtToken);
        return ResponseEntity.ok(response);
    }
}
