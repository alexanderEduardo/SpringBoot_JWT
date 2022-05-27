package com.alex.springboot.app.view.json;

import com.alex.springboot.app.models.entity.Cliente;
import org.springframework.data.domain.Page;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.json.MappingJackson2JsonView;

import java.util.Map;

@Component("listar.json")
public class ClienteListJsonView extends MappingJackson2JsonView {

    @Override
    protected Object filterModel(Map<String, Object> model) {
        Page<Cliente> clientes= (Page<Cliente>) model.get("clientes");
        model.remove("clientes");
        model.remove("page");
        model.remove("prueba");
        model.remove("titulo");
        model.put("clientes",clientes.getContent()); // Esta key clientes esta en el json como JsonArray ya que es una lista
        return super.filterModel(model);
    }
}
