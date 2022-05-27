package com.alex.springboot.app;

import com.alex.springboot.app.auth.handler.LoginSuccessHandler;
import com.alex.springboot.app.models.services.JpaUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.sql.DataSource;

@EnableGlobalMethodSecurity(securedEnabled = true,prePostEnabled = true)
@Configuration
//@EnableWebSecurity
public class SpringSecurityConfig  extends WebSecurityConfigurerAdapter{

    @Bean
    public static BCryptPasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    private LoginSuccessHandler successHandler;
    @Autowired
    public void setLoginSuccessHandler(LoginSuccessHandler successHandler){
        this.successHandler=successHandler;
    }

    @Autowired
    private DataSource dataSource;

    @Autowired
    JpaUserDetailsService userDetailsService;

    @Autowired
    public void configurerGlobal(AuthenticationManagerBuilder builder) throws Exception{
        PasswordEncoder encoder = passwordEncoder();
        /*builder.jdbcAuthentication()*/
        builder.userDetailsService(userDetailsService)
                /*.dataSource(dataSource)*/
                .passwordEncoder(encoder)
                /*.usersByUsernameQuery("select username,password,enabled from users where username=?")*/
                /*.authoritiesByUsernameQuery("select u.username,a.authority from authorities a inner join users u on u.id=a.user_id where u.username = ?")*/
                ;
        //User.UserBuilder users=User.builder().passwordEncoder(pass -> {return encoder.encode(pass)});
        /*User.UserBuilder users=User.builder().passwordEncoder(encoder::encode);
        builder.inMemoryAuthentication()
                .withUser(users.username("admin").password("12345").roles("ADMIN","USER"))
                .withUser(users.username("alexander").password("123").roles("USER"));*/
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/","/css/**","/js/**","/images/**","/listar","/locale").permitAll()
                //.antMatchers("/ver/**","/uploads/**").hasAnyRole("USER")
                //.antMatchers("/form/**").hasAnyRole("ADMIN")
                //.antMatchers("/eliminar/**").hasAnyRole("ADMIN")
                //.antMatchers("/factura/**").hasAnyRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                    .formLogin()
                            .successHandler(successHandler)
                            .loginPage("/login")
                    .permitAll()
                .and()
                .logout().permitAll()
                .and()
                .exceptionHandling().accessDeniedPage("/error_403");
    }
}
