package com.alex.springboot.app.dao;

import com.alex.springboot.app.models.entity.Cliente;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.persistence.Query;
import java.util.List;

@Repository("ClienteDaoImplement")
public class ClienteDaoImplement implements IClienteDao{

    @PersistenceContext
    private EntityManager entityManager;

    @SuppressWarnings("unchecked")
    /*@Transactional(readOnly = true)*/ //se pone en true porque solo lista si fuera u insert lo omitiriamos
    @Override
    public List<Cliente> findAll() {
        entityManager.getEntityManagerFactory().getMetamodel().getEntities();
        entityManager.getTransaction().begin();
        entityManager.getTransaction().commit();
        //Query quey=entityManager.createQuery("FROM Cliente");
        return entityManager.createQuery("FROM Cliente").getResultList() ;
    }

    @Override /*@Transactional(readOnly = true)*/
    public Cliente findOne(Long id) {
        return entityManager.find(Cliente.class,id);
    }

    @Override /*@Transactional*/
    public void save(Cliente cliente) {
        if (cliente.getId() !=null && cliente.getId() > 0 ){
         entityManager.merge(cliente); // actualiza el cliente
        }else{
        entityManager.persist(cliente); //aca se le pone el id recien al cliente (incremental)
        }
    }

    @Override /*@Transactional*/
    public void delete(Long id) {
        Cliente cliente=findOne(id);
        entityManager.remove(cliente);
    }

}
