package com.alex.springboot.app.auth.filter;

import com.alex.springboot.app.auth.SimpleGrantedAuthorityMixin;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

/** Se va ejecutar en cada request**/
public class JWTAuthorizationFilter extends BasicAuthenticationFilter {

    protected static final Key KEY= JWTAuthenticationFilter.SECRET_KEY;
    public JWTAuthorizationFilter(AuthenticationManager authenticationManager) {

        super(authenticationManager);
    }

    /** The entire call is wrapped in a try/catch block in case parsing or signature validation fails.**/
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header=request.getHeader("Authorization");
        if (!requiresAuthentication(header)){
            chain.doFilter(request,response); // continua con los sgtes filtros
            return;
        }

        boolean validoToken;
        Claims token = null;
        try {
            token = Jwts.parserBuilder()
                    .setSigningKey(KEY)
                    .build()
                    .parseClaimsJws(header.replace("Bearer ",""))
                    .getBody();
        validoToken = true;

        }catch (JwtException | IllegalArgumentException e){
            validoToken = false;
        }

        UsernamePasswordAuthenticationToken authenticationToken=null;
        if (validoToken){
            String username = token.getSubject();
            Object roles =token.get("authorities");
            List<GrantedAuthority> authorities = Arrays.asList(new ObjectMapper()
                    .addMixIn(SimpleGrantedAuthority.class, SimpleGrantedAuthorityMixin.class).readValue(roles.toString().getBytes(),SimpleGrantedAuthority[].class));
            System.out.println("---------Imprimiendo los roles-----------");
            for (GrantedAuthority auth:authorities) {
                System.out.println(auth.getAuthority());
            }
            authenticationToken=new UsernamePasswordAuthenticationToken(username,null,authorities);
        }
        //SecurityContext se encarga de manejar el contexto de seguridad.Lo que hacemoes es asignar el obj authenticationToken dentro del contexto
        //Esto autentica al usuario dentro del request(peticion) ya que no estamos usando sesiones queda autenticado dentro de la solicitud del request
        SecurityContextHolder.getContext().setAuthentication(authenticationToken);
        chain.doFilter(request,response);
    }

    protected boolean requiresAuthentication(String header){
        return header != null && header.startsWith("Bearer ");
    }
}
