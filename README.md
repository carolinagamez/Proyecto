# Proyecto

Se realizó un sitio web basado en el sistema de un **banco de sangre**.

---

## Usuario 

Se realizó un usuario personalizado para la base de datos con todos los permisos adecuados para el sistema.
```sql
CREATE USER IF NOT EXISTS 'bank_user'@'localhost' IDENTIFIED BY 'bank_pass';
GRANT ALL PRIVILEGES ON banco_sangre.* TO 'bank_user'@'localhost';
FLUSH PRIVILEGES;

```

## Tablas en la base de datos


Se realizaron las siguientes tablas  en MySQL. Una tabla es para registrar usuarios y otra para asignar un codigo con el rol de cada usuario. Se crearon 3 usuarios el primer tipo de usuario es el Admin, el puede realizar cualquier acción de registro, visualización y gestión de donadores, receptores y usuarios en general. El rol de Medico fue diseñado para registrar, gestionar y visualizar reportes de donadores y receptores, por último, el rol de Inspector únicamente puede visualizar registros, reportes y compatibilidad entre donadores y receptores.

```sql
CREATE DATABASE IF NOT EXISTS banco_sangre CHARACTER SET utf8mb4;
USE banco_sangre;

CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    correo VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    rol ENUM('Admin','Medico','Inspector') NOT NULL DEFAULT 'Inspector'
);

CREATE TABLE IF NOT EXISTS codigos_usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    codigo VARCHAR(20) NOT NULL,
    rol ENUM('Admin', 'Medico', 'Inspector')
);

INSERT INTO codigos_usuarios (codigo, rol) VALUES ('000', 'Admin');
INSERT INTO codigos_usuarios (codigo, rol) VALUES ('001', 'Medico');
INSERT INTO codigos_usuarios (codigo, rol) VALUES ('002', 'Inspector');
```
Se realizó una tabla para registrar los datos de los donadores y otra tabla para los registros de los receptores.
```sql
CREATE TABLE IF NOT EXISTS donadores (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nombre VARCHAR(120) NOT NULL,
  edad INT NOT NULL CHECK (edad > 0 AND edad < 120),
  peso DECIMAL(5,2) NOT NULL CHECK (peso > 0 AND peso < 300),
  tipo ENUM('A','B','AB','O') NOT NULL,
  rh ENUM('+','-') NOT NULL
);

CREATE TABLE IF NOT EXISTS receptores (
  id INT AUTO_INCREMENT PRIMARY KEY,
  nombre VARCHAR(120) NOT NULL,
 edad INT NOT NULL CHECK (edad > 0 AND edad < 120),
  peso DECIMAL(5,2) NOT NULL CHECK (peso > 0 AND peso < 300),
  tipo ENUM('A','B','AB','O') NOT NULL,
  rh ENUM('+','-') NOT NULL
);

```

