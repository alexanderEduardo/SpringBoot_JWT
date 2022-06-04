package com.alex.springboot.app.controllers;

import com.alex.springboot.app.models.services.IClienteService;
import com.alex.springboot.app.view.xml.ClienteList;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.annotation.Secured;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/clientes")
public class ClienteRestController {

    @Autowired @Qualifier("Cliente_ServiceCrudRepository")
    private IClienteService clienteService;

    @Secured("ROLE_ADMIN")
    @GetMapping(value = "/listar")
    public ClienteList listarRest(){
        return new ClienteList(clienteService. findAll());
    }

}
