INSERT INTO clientes (id,nombre,apellido,email,create_at,foto) values (1,'Alexander','Peña','alex@gmail.com','2002-04-11','');
INSERT INTO clientes (id,nombre,apellido,email,create_at,foto) values (2,'Ana','Lucia','ana112@gmail.com','2008-06-25','');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ('Ana','Lucia','ana112@gmail.com','2008-06-25','');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Isaac","Craft","placerat.eget@hotmail.org","2022-12-07",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Amy ","Lynn","lectus.nullam@yahoo.org","2022-11-27",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Igor"," Haynes","a.magna.lorem@outlook.net","2022-12-05",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Zia","Cameron","pede.blandit.congue@icloud.com","2022-12-10",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Odessa","Craig","mi.tempor@protonmail.com","2023-02-26",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Sean","Calderon","lectus.nullam@yahoo.org","2022-11-27",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Jackson","Tillman","a.magna.lorem@outlook.net","2022-12-05",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Lila","Blanchard","vulputate.eu@icloud.net","2022-08-16",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Rooney","Sutton","convallis.est@hotmail.ca","2023-04-04",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Vivian","Guerrero","amet.risus@aol.org","2021-09-05",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Hamilton","Cooper","eros.nam@hotmail.com","2022-09-26",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Lana","Hays","non.leo@yahoo.net","2021-07-26",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Warren","Richardson","auctor.velit@protonmail.org","2021-11-09",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Deborah","Harrison","eget.mollis.lectus@yahoo.ca","2022-10-27",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Pearl","Hobbs","cras.pellentesque.sed@hotmail.net","2021-12-16",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Yardley","Chaney","velit.eget.laoreet@google.com","2021-06-13",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Ahmed","Farrell","aenean@aol.ca","2022-01-16",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Natalie","Mccoy","sed.diam.lorem@protonmail.ca","2022-10-29",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Jasper","Harding","natoque@google.edu","2022-01-30",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Tate","Wilkins","volutpat.ornare@outlook.net","2023-02-24",'');
INSERT INTO `clientes` (`nombre`,`apellido`,`email`,`create_at`,foto) VALUES("Chantale","Burks","lorem.lorem.luctus@aol.com","2023-03-03",'');
INSERT INTO clientes (nombre,apellido,email,create_at,foto) values ("Erin","Howard","ligula.eu@hotmail.com","2022-09-23",'');

/* Populate tabla productos */
INSERT INTO productos (nombre, precio, create_at) VALUES ('Panasonic Pantalla LCD', 26000, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Sony Camara digital DSC-W320B', 45000, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Apple iPod shuffle', 18000, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Sony Notebook Z110', 25000, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Hewlett Packard Multifuncional F2280', 70000, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Bianchi Bicicleta Aro 26', 15000, NOW());
INSERT INTO productos (nombre, precio, create_at) VALUES ('Mica Comoda5Cajones', 30000, NOW());
/* Creamos algunas facturas */
INSERT INTO facturas (descripcion, observacion, cliente_id, create_at) VALUES('Factura equipos de oficina', null, 1, NOW());
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES(1, 1, 1);
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES (2, 1, 4);
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES (1, 1, 5);
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES(1, 1, 7);
INSERT INTO facturas (descripcion, observacion, cliente_id, create_at) VALUES('Factura Bicicleta', 'Alguna nota importante!', 1, NOW());
INSERT INTO facturas_items (cantidad, factura_id, producto_id) VALUES(3, 2, 6);

/* Inserts para Users and authorities*/
INSERT INTO users (username,password) values ("alexander","$2a$10$A/meLAbe6K3KLUWmIsM1FuIlMlAI/x2wvCyq/f6GPYcjP869bG98i");
INSERT INTO users (username,password) values ("admin","$2a$10$Svybs5qs6Fs3GAyCtpX4L.8xbO9SNcThHpYg3JATiGmTsbzYJDvFS");

INSERT INTO authorities (user_id,authority) values (1,"ROLE_USER");
INSERT INTO authorities (user_id,authority) values (2,"ROLE_USER");
INSERT INTO authorities (user_id,authority) values (2,"ROLE_ADMIN");
