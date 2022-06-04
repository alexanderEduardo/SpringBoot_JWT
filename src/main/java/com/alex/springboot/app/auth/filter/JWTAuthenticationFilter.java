package com.alex.springboot.app.auth.filter;

import com.alex.springboot.app.models.entity.Usuario;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.util.*;

public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
       this.authenticationManager=authenticationManager; //Es el encragado de realizar el login segun nuestro service jpa
        setRequiresAuthenticationRequestMatcher(new AntPathRequestMatcher("/api/login","POST"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = this.obtainUsername(request); //request.getParameter("username");
        //username = username != null ? username : "";
        String password = super.obtainPassword(request);
        //password = password != null ? password : "";
        if(username != null && password !=null){
            logger.info("Username desde request parameter (form-data) "+username);
            logger.info("Password desde request parameter (form-data) "+password);
        }else{
            Usuario user=null;
            try {
                System.out.println(request.getInputStream());
                user = new ObjectMapper().readValue(request.getInputStream(),Usuario.class);
                username=user.getUsername();
                password=user.getPassword();
                logger.info("Username desde request parameter (raw): "+username);
                logger.info("Password desde request parameter (raw): "+password);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        //assert username != null : "error username es nulo";
        username = username==null ? "": username;
        username = username.trim();
        UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(username, password);
        return authenticationManager.authenticate(authRequest);
    }

    public static final Key SECRET_KEY = Keys.secretKeyFor(SignatureAlgorithm.HS512);
    public static final KeyPair keyPair = Keys.keyPairFor(SignatureAlgorithm.RS256);// RS256

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // authResult hace referencia a authRequest ya que son lo mismo la difrencia es que authResult tiene seteado el atributo authenticated en TRUE

        //String username = ((User)authResult.getPrincipal()).getUsername();
        String username = authResult.getName();
        //SecretKey secretKey = Keys.secretKeyFor(SignatureAlgorithm.HS512);
        //SecretKey secretKey =Keys.hmacShaKeyFor("some secret key".getBytes());
        SecretKey secretKey = new SecretKeySpec("some.secret.KEY.clave.secreta|@@@###@@@".getBytes(),SignatureAlgorithm.HS512.getJcaName());

        //String secretKeyString = new String (secretKey.getEncoded(), StandardCharsets.UTF_16);
        String secretKeyString = Encoders.BASE64.encode(SECRET_KEY.getEncoded());
        logger.info("key sec :  ".concat(secretKeyString));

        //logger.info("Algorithm: "+keyPair.getPrivate().getAlgorithm()+" format: "+keyPair.getPrivate().getFormat()); //Algorithm: RSA format: PKCS#8
        //String keyPairPrivate = Encoders.BASE64.encode(keyPair.getPrivate().getEncoded());
        //String keyPairPublic = Encoders.BASE64.encode(keyPair.getPublic().getEncoded());
        //logger.info("keyPairPrivate : ".concat(keyPairPrivate));
        //logger.info("keyPairPublic  : ".concat(keyPairPublic));

        Collection<? extends GrantedAuthority> roles=authResult.getAuthorities();
        Claims claims=Jwts.claims();
        claims.put("authorities",new ObjectMapper().writeValueAsString(roles));
        String token = Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .signWith(SECRET_KEY)
                .setIssuedAt(new Date()) //fecha de creacion
                .setExpiration(new Date(System.currentTimeMillis() + 3600000L)) // Seteamos el tiempo de expiracion| El 3600000 hace referencia a 1 hora
                .compact();

        response.addHeader("Authorization","Bearer "+token);

        Map<String,Object> body = new HashMap<>();

        body.put("token",token);
        body.put("user",authResult.getPrincipal()); // Aca no tiene sentido castear ya que al final va ser object
        body.put("mensaje", String.format("Hola %s, has iniciado sesion con exito!",username));

        response.getWriter().write(new ObjectMapper().writeValueAsString(body));
        response.setStatus(200);
        response.setContentType("application/json");
        //super.successfulAuthentication(request, response, chain, authResult);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        Map<String,Object> body = new HashMap<>();
        body.put("mensaje","Error de autentificacion el username y/o el password son incorrectos");
        body.put("error",failed.getMessage());
        response.getWriter().write(new ObjectMapper().writeValueAsString(body)); //de object a json
        response.setStatus(401);
        response.setContentType("application/json");
        //super.unsuccessfulAuthentication(request, response, failed);
    }
}
