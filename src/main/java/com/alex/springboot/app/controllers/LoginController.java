package com.alex.springboot.app.controllers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import java.security.Principal;

@Controller
public class LoginController {

    Logger log= LoggerFactory.getLogger(getClass());
    @GetMapping("/login")
    public String login(@RequestParam(value = "error",required = false) String error,
                        @RequestParam(required = false) String logout,
                        Model model, Principal principal, RedirectAttributes flash){
        int c =1;
        log.info(" count Login ->"+c++);
        if (principal != null ) {//Significa que ya habia iniciado sesion anteriormente
            log.info(" principal != null <--- "+ principal.getName());
            flash.addFlashAttribute("info","Ya ha iniciado sesion anteriormente");
            return "redirect:/";
        }
        if ( error != null ) {
            log.info(" error -> "+error);
            model.addAttribute("error", "Error en el login : Nombre de usuario o contraseña incorrecta , por favor vuelva  a intentarlo");
        }
        if ( logout != null ){
            model.addAttribute("success","Ha cerrado Sesion con xito");
        }
        return "login";
    }


}
