package com.alex.springboot.app.auth.service;


import com.fasterxml.jackson.core.JsonProcessingException;
import io.jsonwebtoken.Claims;
import org.apache.commons.logging.Log;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.io.IOException;
import java.util.List;

public interface JWTService {

    String create(Authentication authResult, Log logger) throws JsonProcessingException;
    boolean validate(String token);
    Claims getClaims(String token);
    String getUsername(String token);
    List<GrantedAuthority> getRoles(String token) throws IOException;
}
