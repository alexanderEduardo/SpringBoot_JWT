package com.alex.springboot.app.dao;

import com.alex.springboot.app.models.entity.Producto;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import java.util.List;

public interface IProductoDao extends CrudRepository<Producto, Long> {

    @Query("select p FROM Producto p WHERE p.nombre LIKE %?1%")
     List<Producto> findByNombre(String term);

     List<Producto> findByNombreLikeIgnoreCase(String term);
    //findProductoByNombre
}
