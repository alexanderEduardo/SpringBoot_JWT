package com.alex.springboot.app.view.xml;

import com.alex.springboot.app.models.entity.Cliente;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.view.xml.MarshallingView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

//El ViewResolver es a traves del nombre del componente o nombre del Bean - BeanNameViewResolver
@Component("listar.xml")
public class ClienteListXmlView extends MarshallingView {

    @Autowired
    public ClienteListXmlView(Jaxb2Marshaller marshaller) {
        super(marshaller);
    }

    @Override
    protected void renderMergedOutputModel(Map<String, Object> model, HttpServletRequest request, HttpServletResponse response) throws Exception {

        Page<Cliente> clientes= (Page<Cliente>) model.get("clientes");

        //quito todos los objetos de mi Map ya que no quiero convertir estos objt en XML
        model.remove("page");
        model.remove("prueba");
        model.remove("titulo");
        model.remove("clientes");

        model.put("clienteList",new ClienteList(clientes.getContent()));

        super.renderMergedOutputModel(model, request, response);
    }
}
