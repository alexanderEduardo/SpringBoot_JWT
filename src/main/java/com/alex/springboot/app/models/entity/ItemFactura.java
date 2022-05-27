package com.alex.springboot.app.models.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import javax.persistence.*;
import java.io.Serializable;

//tiene una relacion unidereccional con "productos"
@Entity @Table(name = "facturas_items")
public class ItemFactura implements Serializable {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private Integer cantidad;

    //Muchos item Factura estan relacionados a un producto
    //Como estamos mapeando producto va crear el campo producto_id en la tabla facturas_item aunque nunca esta demas especificar con JoinColumn
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "producto_id") //entonces la llave foranea en la tabla facturas_items seria prodcuto_id
    @JsonIgnoreProperties({"hibernateLazyInitializer","handler"})
    private Producto producto;

    public Double calcularImporte(){
        return cantidad.doubleValue()* producto.getPrecio();
    }
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public Integer getCantidad() {
        return cantidad;
    }
    public void setCantidad(Integer cantidad) {
        this.cantidad = cantidad;
    }
    public Producto getProducto() {
        return producto;
    }
    public void setProducto(Producto producto) {
        this.producto = producto;
    }

    @Override
    public String toString() {
        return "ItemFactura{" +
                "id=" + id +
                ", cantidad=" + cantidad +
                ", producto=" + producto.getNombre() +
                '}';
    }

    private static final long serialVersionUID=1L;
}
