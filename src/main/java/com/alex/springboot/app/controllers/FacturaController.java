package com.alex.springboot.app.controllers;
import com.alex.springboot.app.models.entity.Cliente;
import com.alex.springboot.app.models.entity.Factura;
import com.alex.springboot.app.models.entity.ItemFactura;
import com.alex.springboot.app.models.entity.Producto;
import com.alex.springboot.app.models.services.IClienteService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.access.annotation.Secured;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import javax.validation.Valid;
import java.util.List;
import java.util.Map;

@Controller
@RequestMapping("/factura")
@Secured("ROLE_ADMIN")
@SessionAttributes("factura") //Tambien es importante que hacemos esto para "persistir" en obj factura con su atributo Cliente
public class FacturaController {
    private final Logger log= LoggerFactory.getLogger(getClass());

    @Autowired @Qualifier("Cliente_ServiceCrudRepository")
    IClienteService clienteService;

    /**Este metodo se usa para desplegar el formulario a la vista es importante mantener el obj factura en la sesion hasta que se procesa el formulario osea hasta que se envie el formulario al metodo guardar ,esto metodo guardar procesa el formulario y persiste la factura en la bd.Nos damos cuenta que la instancia factura viaje entre 2 metodos handler poe ello es necesario agregarla al session atribuute**/
    @GetMapping("/form/{clienteId}")
    public String crear(@PathVariable Long clienteId, Map<String,Object> model, RedirectAttributes flash){
        Cliente cliente=clienteService.findOne(clienteId);
        if(cliente==null){
            flash.addFlashAttribute("error","El cliente no existe en la BD");
            return "redirect:/listar";
        }
        Factura factura=new Factura();
        //seteo el cliente al cual es relacionado mi factura algo asi como ponerle el valor del fk de esa instancia
        factura.setCliente(cliente);
        model.put("factura",factura);
        model.put("titulo","Crear Factura");
        return "factura/form";
    }

    @PostMapping("/form") // 2 3 1
    public String guardar(@Valid Factura factura, BindingResult result, Model model,
                          @RequestParam(name = "item_id[]",required = false) Long[] itemsId,
                              @RequestParam(name = "cantidad[]",required = false) Integer[] cantidad,
                          RedirectAttributes flash, SessionStatus status){
        if (result.hasErrors()){
            model.addAttribute("titulo","Crear Factura");
            /*forward:factura/form*/
            return "factura/form"; //html
        }
        if (itemsId == null || itemsId.length == 0 ){
            model.addAttribute("titulo","Crear Factura");
            model.addAttribute("error","Error: La factura no puede no tener lineas");
            return "factura/form"; //html
        }
        System.out.println("itemsId.length : "+ itemsId.length);
        for (int i = 0; i < itemsId.length; i++) {
            Producto producto= clienteService.findProductById(itemsId[i]);
            ItemFactura linea = new ItemFactura();
            linea.setCantidad(cantidad[i]);
            linea.setProducto(producto);
            factura.addItemFactura(linea);
            log.info("ID: " + itemsId[i] + ",cantidad :"+cantidad[i].toString());
        }
        log.info("------------------HAGO clienteService.saveFactura(factura)----------------");
        clienteService.saveFactura(factura);
        log.info("------------------TERMINA clienteService.saveFactura(factura)-------------");
        status.setComplete();
        flash.addFlashAttribute("success","Factura creada con exito");
        return "redirect:/ver/" + factura.getCliente().getId(); //handler method
    }

    @GetMapping("ver/{id}")
    public String ver(@PathVariable Long id,Model model,RedirectAttributes flash){
        Factura factura = clienteService.fetchByIdWithClienteWithItemFacturaWithProducto(id);
        System.out.println("Factura is ...");
        //Factura factura= clienteService.findFacturabyId(id);
        if(factura == null ){
            flash.addFlashAttribute("error","La Factura no existe en la BD");
            return "redirect:/listar";
        }
        model.addAttribute("factura",factura);
        model.addAttribute("Descripcion_Factura","Factura: ".concat(factura.getDescripcion()));
        return "factura/ver";
    }

    /** Metodo Handler para eliminar una factura se pasa como @PathVariable el id de la Factura relacionada al cliente **/
    @GetMapping(value = "/eliminar/{id}")
    public String eliminarFactura(@PathVariable Long id,RedirectAttributes flash){
        Factura factura=clienteService.findFacturabyId(id);
        if (factura != null){
            log.info("~~ STARTING clienteService.deleteFactura(id) ~~");
            clienteService.deleteFactura(id);
            log.info("~~ ENDING clienteService.deleteFactura(id) ~~");
            flash.addFlashAttribute("success","Factura ~".concat(factura.getDescripcion()).concat("~ ha sido eliminada"));
            return "redirect:/ver/"+factura.getCliente().getId();
        }
        flash.addFlashAttribute("error","La factura no existe en la Base de Datos");
        return "redirect:/ver/"+factura.getCliente().getId();
    }

    /**Cuando falle la validadcion del form y quiera darle a factura/form desde la URL me envia a este metodo handler **/
    @GetMapping("/form")
    public String volver(@SessionAttribute("factura") Factura factura){
        Long idAux=factura.getCliente().getId();
        log.info("WTFFFFFFFFFF"+idAux);
        return "redirect:/factura/form/"+idAux; //handler
    }


    /** produce sirve para generar la respuesta json**/
    @GetMapping(value = "/cargar-productos/{term}",produces = {"application/json"})
    public @ResponseBody List<Producto> cargarProductos(@PathVariable String term){
        //Lo que hace responseBody es suprimir el cargar una vista de thymeleaf y envez de eso  va tomar
        //el return convertido a json y eso lo va poblar dentro del body de la respuesta
        return clienteService.findByNombre(term);
    }


}

