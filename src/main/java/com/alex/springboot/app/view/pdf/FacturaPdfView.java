package com.alex.springboot.app.view.pdf;

import com.alex.springboot.app.models.entity.Factura;
import com.alex.springboot.app.models.entity.ItemFactura;
import com.lowagie.text.Document;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.MessageSource;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.view.document.AbstractPdfView;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.*;
import java.util.Locale;
import java.util.Map;

@Component("factura/ver")
public class FacturaPdfView extends AbstractPdfView {
    @Autowired
    private MessageSource messageSource;
    @Autowired
    private LocaleResolver localeResolver;
    //Document representa el documento PDF de la api iText
    @Override
    protected void buildPdfDocument(Map<String, Object> model, Document document, PdfWriter writer, HttpServletRequest request, HttpServletResponse response) throws Exception {
        Locale locale=localeResolver.resolveLocale(request);
        MessageSourceAccessor sourceAccessor=getMessageSourceAccessor();
        Factura factura=(Factura) model.get("factura");
        PdfPTable table = new PdfPTable(1);
        table.setSpacingAfter(20);
        PdfPCell cell=null;
        cell = new PdfPCell(new Phrase(messageSource.getMessage("text.factura.ver.datos.cliente",null,locale)));
        cell.setBackgroundColor(new Color(84, 121, 180));
        cell.setPadding(8f);
        table.addCell(cell);
        //table.addCell("Datos del Cliente");
        table.addCell(factura.getCliente().getNombre()+""+factura.getCliente().getApellido());
        table.addCell(factura.getCliente().getEmail());

        PdfPTable table2 = new PdfPTable(1);
        table2.setSpacingAfter(20);
        cell = new PdfPCell(new Phrase(messageSource.getMessage("text.factura.ver.datos.factura",null,locale)));
        cell.setBackgroundColor(new Color(113, 79, 245));
        cell.setPadding(8f);
        //table2.addCell("Datos de la factura");
        table2.addCell(cell);
        table2.addCell(sourceAccessor.getMessage("text.cliente.factura.folio")+factura.getId());
        table2.addCell(sourceAccessor.getMessage("text.cliente.factura.descripcion")+factura.getDescripcion());
        table2.addCell(sourceAccessor.getMessage("text.cliente.factura.fecha")+factura.getCreateAt());

        document.add(table);
        document.add(table2);

        PdfPTable table3 = new PdfPTable(4);
        table3.setWidths(new float[] {2.5f,1,1,1});
        table3.addCell(sourceAccessor.getMessage("text.factura.form.item.nombre"));
        table3.addCell(sourceAccessor.getMessage("text.factura.form.item.precio"));
        table3.addCell(sourceAccessor.getMessage("text.factura.form.item.cantidad"));
        table3.addCell("Total");

        for (ItemFactura item: factura.getItems()){
            table3.addCell(item.getProducto().getNombre());
            table3.addCell(item.getProducto().getPrecio().toString());
            cell=new PdfPCell(new Phrase(item.getCantidad().toString()));
            cell.setHorizontalAlignment(PdfPCell.ALIGN_CENTER);
            table3.addCell(cell);
            table3.addCell(item.calcularImporte().toString());
        }

         cell = new PdfPCell(new Phrase("Total: "));
        cell.setColspan(3);
        cell.setHorizontalAlignment(PdfPCell.ALIGN_RIGHT);
        table3.addCell(cell);
        table3.addCell(factura.getTotal().toString());

        document.add(table3);
    }
}
