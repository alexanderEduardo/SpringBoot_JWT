package com.alex.springboot.app.models.entity;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import org.springframework.format.annotation.DateTimeFormat;
import javax.persistence.*;
import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import javax.validation.constraints.*;


@Entity @Table(name = "clientes")
public class Cliente implements Serializable {

    private static final long serialVersionUID = 1L;
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "nombre") @NotEmpty @Size(min = 4,max = 12)
    private String nombre;
    @NotEmpty
    private String apellido;

    @Column(name = "create_at") @NotNull /*@DateTimeFormat(pattern = "yyyy-MM-dd")*/
    @Temporal(TemporalType.DATE) //se guarda con formato fecha en la bd
    @JsonFormat(pattern = "yyyy-MM-dd HHHH:mm:ss")
    private Date createAt;

    @NotEmpty @Email
    private String email;
    //El ONE hace referencia a cliente , es decir , un cliente puede tener muchas Facturas!
    @OneToMany(mappedBy = "cliente",fetch = FetchType.LAZY,cascade = CascadeType.ALL,orphanRemoval = true)
    private List<Factura> facturas;
    private String foto;

    public Cliente() {
        facturas=new ArrayList<>();
    }

    // @PrePersist          //antes de que se guarde en la bd
    public void prePersist(){
        createAt=new Date();
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getApellido() {
        return apellido;
    }

    public void setApellido(String apellido) {
        this.apellido = apellido;
    }

    public Date getCreateAt() {
        return createAt;
    }

    public void setCreateAt(Date createAt) {
        this.createAt = createAt;
    }

    public String getFoto() {
        return foto;
    }

    public void setFoto(String foto) {
        this.foto = foto;
    }

    public void addFactura(Factura factura){
        facturas.add(factura);
    }
    public List<Factura> getFacturas() {
        return facturas;
    }

    public void setFacturas(List<Factura> facturas) {
        this.facturas = facturas;
    }

    @Override
    public String toString() {
        return nombre + " " + apellido;
    }
}
