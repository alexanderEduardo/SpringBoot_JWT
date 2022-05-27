package com.alex.springboot.app.dao;

import com.alex.springboot.app.models.entity.Cliente;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.PagingAndSortingRepository;

public interface IClienteDao_CrudRepository extends PagingAndSortingRepository<Cliente,Long> { // CrudRepository es  similar a JPARepositori solo que este tiene metodo de paginacion
    /*PagingAndSortingRepository <T, ID> extends CrudRepository<T,ID>*/
    //Aqui puede haber querys personalizados ...
    /*@Query("SET  @num := 0;" +
            "UPDATE clientes SET id = @num := (@num+1);" +
            "ALTER TABLE clientes AUTO_INCREMENT =1")
    public void auto_increment();*/
    @Query("select c FROM Cliente c left join fetch c.facturas f where c.id=?1")
     Cliente fetchByIdWithFacturas(Long id);
}
