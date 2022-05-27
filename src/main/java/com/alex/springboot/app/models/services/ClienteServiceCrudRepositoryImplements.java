package com.alex.springboot.app.models.services;

import com.alex.springboot.app.dao.IClienteDao_CrudRepository;
import com.alex.springboot.app.dao.IFacturaDao;
import com.alex.springboot.app.dao.IProductoDao;
import com.alex.springboot.app.models.entity.Cliente;
import com.alex.springboot.app.models.entity.Factura;
import com.alex.springboot.app.models.entity.Producto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
@Service("Cliente_ServiceCrudRepository")
public class ClienteServiceCrudRepositoryImplements implements IClienteService{

    @Autowired
    IClienteDao_CrudRepository iClienteDaoCrudRepo;
    @Autowired
    IProductoDao productoDao;
    @Autowired
    IFacturaDao facturaDao;
    @Override @Transactional(readOnly = true)
    public List<Cliente> findAll() {
        return (List<Cliente>) iClienteDaoCrudRepo.findAll();
    }
    /*Paginacion */
    @Override @Transactional(readOnly = true)
    public Page<Cliente> findAll(Pageable pageable) {
        return iClienteDaoCrudRepo.findAll(pageable);
    }

    @Override @Transactional
    public void save(Cliente cliente) {
        iClienteDaoCrudRepo.save(cliente);
    }

    @Override @Transactional(readOnly = true)
    public Cliente findOne(Long id) {
        return iClienteDaoCrudRepo.findById(id).orElse(null);
    }

    @Override @Transactional(readOnly = true)
    public Cliente fetchByIdWithFacturas(Long id) {
        return iClienteDaoCrudRepo.fetchByIdWithFacturas(id);
    }

    @Override @Transactional
    public void delete(Long id) {
        iClienteDaoCrudRepo.deleteById(id);
    }

    @Override  @Transactional(readOnly = true)
    public List<Producto> findByNombre(String term) {
        return productoDao.findByNombre(term);
    }

    @Override
    @Transactional
    public void saveFactura(Factura factura) {
        facturaDao.save(factura);
    }

    @Override
    @Transactional(readOnly = true) //ya que no modifca la Base de datos
    public Producto findProductById(Long id) {
        return productoDao.findById(id).orElse(null);
    }

    @Override
    @Transactional(readOnly = true)
    public Factura findFacturabyId(Long id) {
        return facturaDao.findById(id).orElse(null);
    }

    @Override
    public void deleteFactura(Long id) {
        facturaDao.deleteById(id);
    }

    @Override
    public Factura fetchByIdWithClienteWithItemFacturaWithProducto(Long id) {
        return facturaDao.fetchByIdWithClienteWithItemFacturaWithProducto(id);
    }

    /*@Override*/
    public void auto_incremental() {
    //    iClienteDaoCrudRepo.auto_increment();
    }
}
