package com.alex.springboot.app.models.services;

import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.util.FileSystemUtils;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service("")
public class IUploadFileServiceImplements implements IUploadFileService{
    private final static String UPLOAD_FOLDER="uploads";
    @Override
    public Resource obtenerRecursoToResponseEntity(String filename)throws MalformedURLException{
        Path pathfoto = Paths.get("uploads").resolve(filename).toAbsolutePath();
        System.out.println("pathFoto2 : " + pathfoto);
        Resource resource = null;
        try {
            resource = new UrlResource(pathfoto.toUri());
            System.out.println("RESOURCE : " + resource);
            if (!resource.exists() && !resource.isReadable()) {
                throw new RuntimeException("Error: no se puede cargar la imagen" + pathfoto.toString());
            }
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        return resource;
    }

    @Override
    public boolean deleteFile(String clienteFoto) {
        System.out.println("DELETE FILE FROM IMPLEMENTS");
        Path rootPath = Paths.get("uploads").resolve(clienteFoto).toAbsolutePath();
        File archivo = rootPath.toFile();
        if (archivo.exists() && archivo.canRead()) {
           return archivo.delete();
        }
        return false;
    }

    @Override
    public void deleteAll() {
        FileSystemUtils.deleteRecursively(Paths.get(UPLOAD_FOLDER).toFile());
    }

    @Override
    public void init() throws IOException {
        Files.createDirectory(Paths.get(UPLOAD_FOLDER));
    }
}
