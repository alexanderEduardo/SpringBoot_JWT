package com.alex.springboot.app.models.entity;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.persistence.*;
import javax.validation.constraints.NotEmpty;
import javax.xml.bind.annotation.XmlTransient;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/*Una factura contiene muchos elementos Items , pero por otro lado la clase ItemFactura no tiene relacion
* con factura  ya que no es necesario ya que en ningun momento vamos a consultar cual el factura de un
* item en particular .La idea es ver el detalle de la factura y mostras cuales son sus itemFactura )
* La relacion si bien es de OneToMany seria unidireccional a diferencia de Cliente-Factura que es bidirecc...*/
@Entity @Table(name = "facturas")
public class Factura implements Serializable {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String observacion;
    @NotEmpty
    private String descripcion;

    @Temporal(TemporalType.DATE)
    @Column(name = "create_at")
    private Date createAt;

    //muchas instancias de factura estan asociadas a una sola instancia de cliente es decir la clase factura
    // puede tener un solo cliente ,
    @ManyToOne(fetch = FetchType.LAZY)
    //@JoinColumn(name = "cliente_id") // se podria poner esto
    private Cliente cliente;

    //Una Factura esta relacionada a muchos item Factura || cascade: si eliminamos una factura entoces tmb se eleminaran sus hijos
    @OneToMany(fetch = FetchType.LAZY,cascade = CascadeType.ALL,orphanRemoval = true)
    @JoinColumn(name = "factura_id") //esto hace que tengamos una foreign key en la tabla facturas_items(la latabla de la relacion )
    private List<ItemFactura> items;

    public Factura() {
        this.items=new ArrayList<>();
    }

    @PrePersist
    public void prePersist(){
        createAt=new Date();    //esto hace que no sea necesario una fecha en el formulario ya que es una fecha de interna creacion
    }

    public void addItemFactura(ItemFactura item){
        this.items.add(item);
    }
    public Double getTotal(){ //total de items
        double total=0.0;
        for (int i = 0; i < items.size(); i++) {
            total+=items.get(i).calcularImporte();
        }
        return total;
    }
    public Long getId() {
        return id;
    }
    public void setId(Long id) {
        this.id = id;
    }
    public String getDescripcion() {
        return descripcion;
    }
    public void setDescripcion(String descripcion) {
        this.descripcion = descripcion;
    }
    public String getObservacion() {
        return observacion;
    }
    public void setObservacion(String observacion) {
        this.observacion = observacion;
    }
    public Date getCreateAt() {
        return createAt;
    }
    public void setCreateAt(Date createAt) {
        this.createAt = createAt;
    }
    @XmlTransient @JsonIgnore
    public Cliente getCliente() {
        return cliente;
    }
    public void setCliente(Cliente cliente) {
        this.cliente = cliente;
    }
    public List<ItemFactura> getItems() {
        return items;
    }
    public void setItems(List<ItemFactura> items) {
        this.items = items;
    }
    private static final long serialVersionUID=1L;
}
