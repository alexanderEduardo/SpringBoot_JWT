package com.alex.springboot.app.models.services;

import org.springframework.core.io.Resource;

import java.io.IOException;
import java.net.MalformedURLException;

public interface IUploadFileService {
    Resource obtenerRecursoToResponseEntity(String filename) throws MalformedURLException;
    boolean deleteFile(String clienteFoto);

    public void deleteAll();
    public void init() throws IOException;
}
