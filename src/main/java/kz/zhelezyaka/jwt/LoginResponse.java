package kz.zhelezyaka.jwt;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class LoginResponse {
    private String username;
    private List<String> roles;
    private String jwtToken;
}
