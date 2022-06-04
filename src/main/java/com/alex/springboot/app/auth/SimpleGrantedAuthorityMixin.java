package com.alex.springboot.app.auth;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public abstract class SimpleGrantedAuthorityMixin {

    //Esta es una marca para indicar que este es ell construcor por defecto cuando se creen los objetos authorities a partir del JSON
    // @JsonProperty("authority") es authority porque ese es el nombre que tiene en el json lo podemos comprobar en la pag web de jwt.io desencriptando el token
    @JsonCreator
    public SimpleGrantedAuthorityMixin(@JsonProperty("authority") String role) {
    }
}
