package com.alex.springboot.app.models.services;

import com.alex.springboot.app.dao.IClienteDao;
import com.alex.springboot.app.models.entity.Cliente;
import com.alex.springboot.app.models.entity.Factura;
import com.alex.springboot.app.models.entity.Producto;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;


import java.util.List;

@Service("ClienteServiceImpls") //fascade Un unico punto de acceso a daos o repositorys . Aca podemos operar con diferentes clases Dao
public class ClienteServiceImplements  implements IClienteService{

    /**Aca podriamos tener diferentes DAO y dentro del service accedemos a los distintos daos
     * con un unico punto de acceso . Aca en el service podemos manegar la transaccion sin tener que implementar
     * las anotaciones transacccional en el dao **/
    @Autowired /*@Qualifier("")*/
    private IClienteDao clienteDao;

    @Override @Transactional(readOnly = true)
    public List<Cliente> findAll() {
        return clienteDao.findAll();
    }

    @Override
    public Page<Cliente> findAll(Pageable pageable) {
        return null;
    }

    @Override @Transactional
    public void save(Cliente cliente) {
            clienteDao.save(cliente);

    }

    @Override @Transactional(readOnly = true)
    public Cliente findOne(Long id) {
        return clienteDao.findOne(id);
    }

    @Override
    public Cliente fetchByIdWithFacturas(Long id) {
        return null;
    }

    @Override @Transactional
    public void delete(Long id) {
        clienteDao.delete(id);
    }

    @Override @Transactional(readOnly = true)
    public List<Producto> findByNombre(String term) {
        return null;
    }

    @Override
    public void saveFactura(Factura factura) {

    }

    @Override
    public Producto findProductById(Long id) {
        return null;
    }

    @Override
    public Factura findFacturabyId(Long id) {
        return null;
    }

    @Override
    public void deleteFactura(Long id) {

    }

    @Override
    public Factura fetchByIdWithClienteWithItemFacturaWithProducto(Long id) {
        return null;
    }


    public void auto_incremental() {

    }
}
