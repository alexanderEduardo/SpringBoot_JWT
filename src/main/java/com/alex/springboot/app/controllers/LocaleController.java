package com.alex.springboot.app.controllers;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;

@Controller
public class LocaleController {

    /**Se encarga se manejar la respuesta y redirigir a la ultima pagina en la que estabamos**/
    @GetMapping("/locale")
    public String locale(HttpServletRequest request){
        //El refrer la referencia a la ultimaURL o sea el link de ultima pag
        String  ultimaURL = request.getHeader("referer");
        System.out.println("LAST URL -> ".concat(ultimaURL));
      return "redirect:".concat(ultimaURL);
    }
}
