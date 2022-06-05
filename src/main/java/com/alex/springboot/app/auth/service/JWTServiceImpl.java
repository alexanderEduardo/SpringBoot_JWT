package com.alex.springboot.app.auth.service;

import com.alex.springboot.app.auth.SimpleGrantedAuthorityMixin;
import com.alex.springboot.app.auth.filter.JWTAuthenticationFilter;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.apache.commons.logging.Log;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@Component
public class JWTServiceImpl implements JWTService{

    public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    @Override
    public String create(Authentication authResult, Log logger) throws JsonProcessingException {
        String username = authResult.getName();
        String secretKeyString = Encoders.BASE64.encode(SECRET_KEY.getEncoded());
        logger.info("~~Secret Key is:  ".concat(secretKeyString));
        Collection<? extends GrantedAuthority> roles=authResult.getAuthorities();
        Claims claims= Jwts.claims();
        claims.put("authorities",new ObjectMapper().writeValueAsString(roles));
        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .signWith(SECRET_KEY)
                .setIssuedAt(new Date()) //fecha de creacion
                .setExpiration(new Date(System.currentTimeMillis() + 3600000L)) // Seteamos el tiempo de expiracion| El 3600000 hace referencia a 1 hora
                .compact();
        return token;
    }

    @Override
    public boolean validate(String header) {
        try {
            getClaims(header);
            return true;
        }catch (JwtException | IllegalArgumentException e){
            return false;
        }
    }

    @Override
    public Claims getClaims(String header) {
        return Jwts.parserBuilder()
                .setSigningKey(SECRET_KEY)
                .build()
                .parseClaimsJws(header.replace("Bearer ",""))
                .getBody();
    }

    @Override
    public String getUsername(String header) {
        return getClaims(header).getSubject();
    }

    @Override
    public List<GrantedAuthority> getRoles(String header) throws IOException {
        Object roles = getClaims(header).get("authorities");
        return Arrays.asList(new ObjectMapper()
                .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class)
                .readValue(roles.toString().getBytes(),SimpleGrantedAuthority[].class));
    }

}
