package com.alex.springboot.app.dao;

import com.alex.springboot.app.models.entity.Cliente;


import org.springframework.stereotype.Repository;

import java.util.List;

public interface IClienteDao  {
    public List<Cliente> findAll();
    public void save(Cliente cliente);
    public Cliente findOne(Long id);
    public void delete(Long id);
}
