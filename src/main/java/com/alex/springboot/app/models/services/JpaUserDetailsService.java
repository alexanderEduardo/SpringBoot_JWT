package com.alex.springboot.app.models.services;

import com.alex.springboot.app.dao.IUsuarioDaoRepository;
import com.alex.springboot.app.models.entity.Role;
import com.alex.springboot.app.models.entity.Usuario;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

@Service("jpaUserDetailsService")
public class JpaUserDetailsService implements UserDetailsService {
    private final Logger logger= LoggerFactory.getLogger(JpaUserDetailsService.class);
    @Autowired
    public IUsuarioDaoRepository usuarioDaoRepository;

    @Override @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario usuario = usuarioDaoRepository.findByUsername(username);
        if ( usuario == null){
            logger.info("Error login el usuario no existe '"+username+"'");
           throw new UsernameNotFoundException("Username "+username +"no existe en el sistema");
        }

        List<GrantedAuthority> authorities = new ArrayList<GrantedAuthority>();
        for (Role role:usuario.getRoles()) {
            logger.info("Role : " + role.getAuthority());
            authorities.add(new SimpleGrantedAuthority(role.getAuthority()));
        }
        if ( authorities.isEmpty()){
            logger.info("Error login el usuario '"+username+"' no tiene Roles asignados! ");
            throw new UsernameNotFoundException("Error login el usuario '"+username+"' no tiene Roles asignados! ");
        }
        return new User(usuario.getUsername(),usuario.getPassword()
                ,usuario.getEnabled(),true,true,true,authorities);
    }
}
