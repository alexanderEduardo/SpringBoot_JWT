package com.alex.springboot.app.util.paginator;

import org.springframework.data.domain.Page;

import java.util.ArrayList;
import java.util.List;

public class PageRender<T> {
    private String url;
    private Page<T> page;
    private final int totalPaginas;
    private final int numberOfElementsPerPage;
    private final int paginaActual;
    private List<PageItem> paginas;
    public PageRender(String url, Page<T> page) {
        this.url = url;
        this.page = page;
        this.paginas=new ArrayList<PageItem>();
        numberOfElementsPerPage=page.getSize(); //4
        totalPaginas=page.getTotalPages();   //7
        paginaActual=page.getNumber()+1; // 0 + 1
        int desde,hasta;
        if(totalPaginas<=numberOfElementsPerPage){ //7 < 4
            desde=1;
            hasta=totalPaginas;
        }else{
            if (paginaActual<=numberOfElementsPerPage/2){  // 1 2
                desde=1;
                hasta=numberOfElementsPerPage;
            }else if (paginaActual >= totalPaginas - numberOfElementsPerPage/2){ // 5 6 7
                desde=totalPaginas - numberOfElementsPerPage + 1 ; //2  .. 7 - 4 + 1
                System.out.println("desde: "+desde);
                hasta=numberOfElementsPerPage; //4
            }else{ //4
                desde=paginaActual - numberOfElementsPerPage/2; //2
                hasta=numberOfElementsPerPage; //4
            }
        }
        for (int i=0;i<hasta;i++){ // valor max i=3 primer ciclo
            System.out.println("for !!");
            paginas.add(new PageItem(desde+i,paginaActual==desde+i));
        }
    }
    public boolean isFirst(){
        return page.isFirst();
    }
    public boolean isLast(){
        return page.isLast();
    }
    public boolean isHasNext(){
        return page.hasNext();
    }
    public boolean isHasPrevious(){
        return page.hasPrevious();
    }
    public String getUrl() {
        return url;
    }

    public int getTotalPaginas() {
        return totalPaginas;
    }

    public int getPaginaActual() {
        return paginaActual;
    }

    public List<PageItem> getPaginas() {
        return paginas;
    }
}
