package com.alex.springboot.app.models.services;

import com.alex.springboot.app.models.entity.Cliente;
import com.alex.springboot.app.models.entity.Factura;
import com.alex.springboot.app.models.entity.Producto;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface IClienteService {
    public List<Cliente> findAll();
    public Page<Cliente> findAll(Pageable pageable);
    public void save(Cliente cliente);
    public Cliente findOne(Long id);
    public Cliente fetchByIdWithFacturas(Long id);
    public void delete(Long id);
    public List<Producto> findByNombre(String term);
   // public void auto_incremental();
    public void saveFactura(Factura factura);
    public Producto findProductById(Long id);
    public Factura findFacturabyId(Long id);
    public void deleteFactura(Long id);
    public Factura fetchByIdWithClienteWithItemFacturaWithProducto(Long id);
}
