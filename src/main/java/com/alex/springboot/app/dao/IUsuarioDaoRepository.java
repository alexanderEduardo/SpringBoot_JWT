package com.alex.springboot.app.dao;

import com.alex.springboot.app.models.entity.Usuario;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;

public interface IUsuarioDaoRepository extends CrudRepository<Usuario,Long> {

    Usuario findByUsername(String username);

    @Query("select u FROM Usuario u WHERE u.username = ?1")
    Usuario fetchByUsername(String username);
}
