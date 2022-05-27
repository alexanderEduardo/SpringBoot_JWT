package com.alex.springboot.app.view.xml;

import com.alex.springboot.app.models.entity.Cliente;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import java.util.List;

@XmlRootElement(name = "clientes")
public class ClienteList {

    @XmlElement(name = "cliente")
    private List<Cliente> clientes;

    public ClienteList(List<Cliente> clientes) {
        this.clientes = clientes;
    }

    public ClienteList() {
    }

    public List<Cliente> getClientes() {
        return clientes;
    }
}
