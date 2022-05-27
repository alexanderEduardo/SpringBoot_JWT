package com.alex.springboot.app;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.oxm.jaxb.Jaxb2Marshaller;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

import java.nio.file.Paths;
import java.util.Locale;

@Configuration
public class MVC_config implements WebMvcConfigurer {
    private final Logger logger= LoggerFactory.getLogger(getClass());
    //Para agregar recursos estaticos a nuestro proyecto

      /*@Override
    public void addResourceHandlers(ResourceHandlerRegistry registry) {
        WebMvcConfigurer.super.addResourceHandlers(registry);       */
        //vamos a usar registry para registrar nuestra nueva ruta
        //se configura como directorio estatico
        /*registry.addResourceHandler("/upload/**")
                .addResourceLocations("file:C:/Recursos_IMG/Spring1/");*/
        //Pongo el pongo el toURI para que incluye el esquema file
       /*String resourcePath= Paths.get("uploads").toAbsolutePath().toUri().toString();
        System.out.println("PATH conf : "+resourcePath);
        registry.addResourceHandler("/upload/**")
                .addResourceLocations(resourcePath);
    } */

    public void addViewControllers(ViewControllerRegistry registry){
        registry.addViewController("/error_403").setViewName("error_403");
    }

    @Bean
    public LocaleResolver localeResolver(){
        SessionLocaleResolver localeResolver = new SessionLocaleResolver();
        localeResolver.setDefaultLocale(new Locale("es","ES"));
        return localeResolver;
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor(){
       LocaleChangeInterceptor localeChangeInterceptor = new LocaleChangeInterceptor();
       localeChangeInterceptor.setParamName("lang");
       return localeChangeInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(localeChangeInterceptor());
    }

    //Este bean nos sirve para convertir nuestro entity(Object) en xml
    @Bean
    public Jaxb2Marshaller jaxb2Marshaller(){
        Jaxb2Marshaller marshaller = new Jaxb2Marshaller();
        marshaller.setClassesToBeBound(new Class[]{com.alex.springboot.app.view.xml.ClienteList.class});
        return marshaller;
    }
}
