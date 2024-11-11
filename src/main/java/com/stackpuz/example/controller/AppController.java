package com.stackpuz.example.controller;

import java.security.Principal;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Controller
public class AppController {

    @Autowired
    private String jwtSecret;

    @GetMapping("/user")
    public ResponseEntity<?> getUser(Principal principal) {
        Map<String, String> user = new HashMap<String, String>();
        user.put("name", principal.getName());
        return ResponseEntity.ok(user);
    }

    @PostMapping("/login")
    public ResponseEntity<?> Login(@RequestBody Map<String, String> login) throws Exception {
        String name = login.get("name");
        if (name.equals("admin") && login.get("password").equals("1234")) {
            UsernamePasswordAuthenticationToken authenToken = new UsernamePasswordAuthenticationToken(name, null);
            SecurityContextHolder.getContext().setAuthentication(authenToken);
            String token = Jwts.builder()
                .setSubject(name)
                .setExpiration(new Date(System.currentTimeMillis() + (60 * 60 * 24 * 1000)))
                .signWith(SignatureAlgorithm.HS256, jwtSecret).compact();
            Map<String, Object> response = new HashMap<String, Object>();
            response.put("token", token);
            return ResponseEntity.ok(response);
        }
        return ResponseEntity.status(400).build();
    }
}