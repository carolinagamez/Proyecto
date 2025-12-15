const express = require('express');
const app = express();
const multer = require('multer');
const xlsx = require('xlsx');
const path = require('path');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
require('dotenv').config();
const upload = multer({ dest: 'uploads/' });
//timezone: 'America/Tijuana'

// Middleware para procesar formularios y JSON
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Configuración de la sesión
app.use(session({
  secret: 'secretKey',
  resave: false,
  saveUninitialized: false,
}));

// Middleware de login
function requireLogin(req, res, next) {
  if (!req.session.userId) {   
    return res.redirect('/login');
  }
  next();
}


//Configuración de la BD
const connection = mysql.createConnection({
  host: process.env.DB_HOST,       // Host desde .env
  user: process.env.DB_USER,       // Usuario desde .env
  password: process.env.DB_PASS,   // Contraseña desde .env
  database: process.env.DB_NAME    // Nombre de la base de datos desde .env
});

//Conectar a la BD
connection.connect(err => {
  if (err) {
    console.error('Error al conectar con la base de datos:', err);
    return;
  }
  console.log('Conexión exitosa a la base de datos');
});

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, 'public')));

// Configuración de puerto
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor en funcionamiento en el puerto ${PORT}`));

// Login
app.post('/login', (req, res) => {
  const { nombre, password } = req.body;

  connection.query('SELECT * FROM usuarios WHERE nombre = ?', [nombre], async (err, results) => {
    if (err) {
      console.error('Error MySQL en login:', err);
      return res.send(`
        <html>
        <head> <link rel="stylesheet" href="/bootstrap/bootstrap.min.css"><link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
       <link rel="stylesheet" href="/styles.css"><title>Error</title></head>
        <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
        <div class="text-center">
          <h1 class="text-danger">Error en el servidor</h1>
          <button onclick="window.location.href='/login'" class="btn btn-danger mt-3">Volver</button>
        </div> 
        </body>
        </html>
      `);
    }

    if (results.length === 0) {
      return res.send(`
       <html>
      <head> <link rel="stylesheet" href="/bootstrap/bootstrap.min.css"><link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
      <link rel="stylesheet" href="/styles.css"><title>Usuario no encontrado</title></head>
      <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
      <div class="text-center">
      <h1 class="text-danger"> Usuario no encontrado</h1>
      <button onclick="window.location.href='/login'" class="btn btn-danger mt-3">Volver</button>
      </div>
      </body>
      </html>
      `);
    }

    const user = results[0];
    const ok = await bcrypt.compare(password, user.password_hash);

    if (!ok) {
      return res.send(`
        <html>
        <head><link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
<link rel="stylesheet" href="/styles.css"><title>Contraseña incorrecta</title></head>
        <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
        <div class="text-center">
          <h1 class="text-danger">Contraseña incorrecta</h1>
          <button onclick="window.location.href='/login'" class="btn btn-danger mt-3">Volver</button>
        </div>
        </body>
        </html>
      `);
    }

    // Guardar sesión y redirigir
    req.session.userId = user.id;
    req.session.rol = user.rol;
    res.redirect('/');
  });
});

// Middleware para roles
function requireRole(...roles) {
  return (req, res, next) => {
    if (req.session.rol && roles.includes(req.session.rol)) {  
      next();
    } else {
      let html = `
        <html>
        <head>
          <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
          <title>Error</title>
        </head>
        <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
         <div class="text-center">
          <h1  class="text-danger">Acceso denegado.</h1>
          <button onclick="window.location.href='/'" class="btn btn-danger mt-3">Volver</button>
          </div>
        </body>
        </html>
      `;
      return res.send(html);
    }
  };
}
app.post('/registrar', async (req, res) => {
  const { nombre, password, correo, codigo } = req.body;

  // Validar campos
  if (!nombre || !password || !correo || !codigo) {
    return res.send(`
      <html>
      <head><link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
<title>Error</title></head>
      <body>
        <h1>Todos los campos son obligatorios</h1>
        <button onclick="window.location.href='/registrar'">Volver</button>
      </body>
      </html>
    `);
  }

  // Verificar código de acceso
  connection.query('SELECT rol FROM codigos_usuarios WHERE codigo = ?', [codigo], async (err, results) => {
    if (err) {
      console.error('Error MySQL al verificar código:', err);
      return res.send('Error al verificar el código de acceso.');
    }

    if (results.length === 0) {
      return res.send(`
        <html>
        <head><link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
<title>Error</title></head>
        <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
         <div class="text-center">
          <h1 h1  class="text-danger">Código de acceso inválido</h1>
          <button onclick="window.location.href='/registrar'" class="btn btn-danger mt-3">Volver</button>
        </div>
        </body>
        </html>
      `);
    }

    const rol = results[0].rol;
    const passwordHash = await bcrypt.hash(password, 10);

    // Registrar usuarios
    connection.query(
      'INSERT INTO usuarios (nombre, correo, password_hash, rol) VALUES (?, ?, ?, ?)',
      [nombre, correo, passwordHash, rol],
      (err) => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY') {
            return res.send(`
              <html>
              <head><link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
             <title>Error</title></head>
              <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
              <div class="text-center">
                <h1 class="text-danger">Ese correo ya ha sido registrado</h1>
                <button onclick="window.location.href='/registrar'" class="btn btn-danger mt-3">Volver</button>
               </div> 
              </body>
              </html>
            `);
          }
          console.error('Error MySQL al registrar usuario:', err);
          return res.send('Error al registrar usuario.');
        }

   return res.send(`
          <html>
          <head><link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
<title>Registro exitoso</title></head>
          <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
         <div class="text-center">
            <h1 class="text-success">Usuario registrado correctamente</h1>
            <button onclick="window.location.href='/login'"  class="btn btn-success mt-3"> Inciar sesion </button>
            </div>
          </body>
          </html>
        `);
      }
    );
  });
});

// Rutas
app.get('/', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/registrar', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'registro.html'));
});

//Cerrar sesion
app.get('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) {
      console.error('Error al cerrar sesión:', err);
      return res.send('Error al cerrar sesión');
    }
    res.redirect('/login');
  });
});

// Mostrar tabla de usuarios
app.get('/ver-usuarios', (req, res) => {
  if (req.session.rol !== 'Admin') return res.redirect('/');

  connection.query('SELECT * FROM usuarios', (err, resultados) => {
    if (err) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
          <head>
            <meta charset="UTF-8">
            <title>Error</title>
            <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
            <link rel="stylesheet" href="/styles.css">
          </head>
          <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
            <div class="text-center">
              <h1 class="text-danger"> Error al cargar usuarios</h1>
              <button onclick="window.location.href='/'" class="btn btn-danger mt-3">Volver al inicio</button>
            </div>
          </body>
        </html>
      `);
    }

    let tabla = `
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8">
        <title>Gestión de Usuarios</title>
        <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <div class="container mt-5">
          <h2 class="text-rojo text-center mb-4">Gestión de Usuarios</h2>
          <table class="table table-bordered table-hover shadow-sm">
            <thead class="table-info">
              <tr>
                <th>ID</th>
                <th>Nombre</th>
                <th>Correo</th>
                <th>Gestionar rol</th>
                <th>Eliminar usuario</th>
              </tr>
            </thead>
            <tbody>
    `;

    resultados.forEach(u => {
      tabla += `
        <tr>
          <td>${u.id}</td>
          <td>${u.nombre}</td>
          <td>${u.correo}</td>
          <td>
            <form action="/actualizar-rol" method="POST" style="display:flex; align-items:center; gap:5px;">
              <input type="hidden" name="id" value="${u.id}">
              <select name="rol" class="form-select form-select-sm">
                <option ${u.rol === 'Admin' ? 'selected' : ''}>Admin</option>
                <option ${u.rol === 'Medico' ? 'selected' : ''}>Medico</option>
                <option ${u.rol === 'Inspector' ? 'selected' : ''}>Inspector</option>
              </select>
              <button type="submit" class="btn btn-success btn-sm">Actualizar</button>
            </form>
          </td>
          <td>
            <form action="/eliminar-usuario" method="POST" onsubmit="return confirm('¿Eliminar usuario?')" style="display:inline;">
              <input type="hidden" name="id" value="${u.id}">
              <button type="submit" class="btn btn-danger btn-sm">Eliminar</button>
            </form>
          </td>
        </tr>
      `;
    });

    tabla += `
            </tbody>
          </table>
          <div class="text-center mt-4">
            <a href="/" class="btn btn-info">Volver al inicio</a>
          </div>
        </div>
      </body>
      </html>
    `;

    res.send(tabla);
  });
});


// Actualizar rol
app.post('/actualizar-rol', (req, res) => {
  
  if (req.session.rol !== 'Admin') {
    return res.send(`
      <!DOCTYPE html>
      <html lang="es">
        <head>
          <meta charset="UTF-8">
          <title>Acceso denegado</title>
          <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
          <link rel="stylesheet" href="/styles.css">
        </head>
        <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
          <div class="text-center">
            <h1 class="text-danger"> Acceso denegado</h1>
            <p>No tienes permisos para actualizar roles.</p>
            <button onclick="window.location.href='/'" class="btn btn-danger mt-3">Volver al inicio</button>
          </div>
        </body>
      </html>
    `);
  }

  const { id, rol } = req.body;

  connection.query('UPDATE usuarios SET rol = ? WHERE id = ?', [rol, id], (err) => {
    if (err) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
          <head>
            <meta charset="UTF-8">
            <title>Error</title>
            <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
            <link rel="stylesheet" href="/styles.css">
          </head>
          <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
            <div class="text-center">
              <h1 class="text-danger"> Error al actualizar rol</h1>
              <button onclick="window.location.href='/ver-usuarios'" class="btn btn-danger mt-3">Volver</button>
            </div>
          </body>
        </html>
      `);
    }

    // Autocambio de rol
    if (req.session.userId == id) {
      req.session.rol = rol;
    }

    return res.send(`
      <!DOCTYPE html>
      <html lang="es">
        <head>
          <meta charset="UTF-8">
          <title>Confirmación</title>
          <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
          <link rel="stylesheet" href="/styles.css">
        </head>
        <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
          <div class="text-center">
            <h1 class="text-success"> Rol actualizado correctamente</h1>
            <button onclick="window.location.href='/ver-usuarios'" class="btn btn-success mt-3">Volver</button>
          </div>
        </body>
      </html>
    `);
  });
});

// Eliminar usuario
app.post('/eliminar-usuario', (req, res) => {
  const { id } = req.body;
  connection.query('DELETE FROM usuarios WHERE id = ?', [id], (err) => {
    if (req.session.rol !== 'Admin') {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
          <head>
            <meta charset="UTF-8">
            <title>Error</title>
            <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
            <link rel="stylesheet" href="/styles.css">
          </head>
          <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
            <div class="text-center">
              <h1 class="text-danger"> Error al eliminar usuario</h1>
              <button onclick="window.location.href='/ver-usuarios'" class="btn btn-danger mt-3">Volver</button>
            </div>
          </body>
        </html>
      `);
    }

    return res.send(`
      <!DOCTYPE html>
      <html lang="es">
        <head>
          <meta charset="UTF-8">
          <title>Confirmación</title>
          <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
          <link rel="stylesheet" href="/styles.css">
        </head>
        <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
          <div class="text-center">
            <h1 class="text-success"> Usuario eliminado correctamente</h1>
            <button onclick="window.location.href='/ver-usuarios'" class="btn btn-success mt-3">Volver</button>
          </div>
        </body>
      </html>
    `);
  });
});

app.get('/tipo-usuario', (req, res) => {
  if (!req.session.userId) {
    return res.json({ rol: null });
  }
  res.json({ rol: req.session.rol });
});

app.get('/registrar-donador', requireRole('Admin', 'Medico'), (req, res) => {
  res.sendFile(__dirname + '/public/donadores.html');
});

app.get('/registrar-receptor', requireRole('Admin', 'Medico'), (req, res) => {
  res.sendFile(__dirname + '/public/receptores.html');
});

app.post('/registrar-donador', requireRole('Admin', 'Medico'), (req, res) => {
  const { nombre, edad, peso, tipo, rh } = req.body;
  const query = 'INSERT INTO donadores (nombre, edad, peso, tipo, rh) VALUES (?, ?, ?, ?, ?)';
  const valores = [nombre, edad, peso, tipo, rh];

  connection.query(query, valores, (err) => {
    if (err) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head><meta charset="UTF-8"><title>Error</title>
        <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
        <link rel="stylesheet" href="/styles.css"></head>
        <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
          <div class="text-center">
            <h1 class="text-danger">Error al registrar donador</h1>
            <button onclick="window.location.href='/registrar-donador'" class="btn btn-danger mt-3">Volver</button>
          </div>
        </body>
        </html>
      `);
    }

    return res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head><meta charset="UTF-8"><title>Confirmación</title>
      <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
      <link rel="stylesheet" href="/styles.css"></head>
      <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
        <div class="text-center">
          <h1 class="text-success">Donador registrado correctamente</h1>
          <button onclick="window.location.href='/registrar-donador'" class="btn btn-success mt-3">Registrar otro</button>
          <button onclick="window.location.href='/'" class="btn btn-rojo mt-2">Volver al inicio</button>
        </div>
      </body>
      </html>
    `);
  });
});

app.post('/registrar-receptor', requireRole('Admin', 'Medico'), (req, res) => {
  const { nombre, edad, peso, tipo, rh } = req.body;
  const query = 'INSERT INTO receptores (nombre, edad, peso, tipo, rh) VALUES (?, ?, ?, ?, ?)';
  const valores = [nombre, edad, peso, tipo, rh];

  connection.query(query, valores, (err) => {
    if (err) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head><meta charset="UTF-8"><title>Error</title>
        <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
        <link rel="stylesheet" href="/styles.css"></head>
        <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
          <div class="text-center">
            <h1 class="text-danger">Error al registrar receptor</h1>
            <button onclick="window.location.href='/registrar-receptor'" class="btn btn-danger mt-3">Volver</button>
          </div>
        </body>
        </html>
      `);
    }

    return res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head><meta charset="UTF-8"><title>Confirmación</title>
      <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
      <link rel="stylesheet" href="/styles.css"></head>
      <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
        <div class="text-center">
          <h1 class="text-success">Receptor registrado correctamente</h1>
          <button onclick="window.location.href='/registrar-receptor'" class="btn btn-success mt-3">Registrar otro</button>
          <button onclick="window.location.href='/'" class="btn btn-rojo mt-2">Volver al inicio</button>
        </div>
      </body>
      </html>
    `);
  });
});

//Ver tablas de registros
app.get('/ver-registros', requireRole('Admin', 'Medico', 'Inspector'), (req, res) => {
  res.sendFile(__dirname + '/public/ver-registros.html');
});

app.get('/api/registros', requireRole('Admin', 'Medico', 'Inspector'), (req, res) => {
  const queryDonadores = 'SELECT * FROM donadores';
  const queryReceptores = 'SELECT * FROM receptores';

  connection.query(queryDonadores, (err1, donadores) => {
    if (err1) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head>
          <meta charset="UTF-8">
          <title>Error</title>
          <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
          <link rel="stylesheet" href="/styles.css">
        </head>
        <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
          <div class="text-center">
            <h1 class="text-danger">Error al cargar donadores</h1>
            <p>Ocurrió un problema al consultar la base de datos.</p>
            <button onclick="window.location.href='/'" class="btn btn-danger mt-3">Volver al inicio</button>
          </div>
        </body>
        </html>
      `);
    }

    connection.query(queryReceptores, (err2, receptores) => {
      if (err2) {
        return res.send(`
          <!DOCTYPE html>
          <html lang="es">
          <head>
            <meta charset="UTF-8">
            <title>Error</title>
            <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
            <link rel="stylesheet" href="/styles.css">
          </head>
          <body class="d-flex justify-content-center align-items-center vh-100 bg-light">
            <div class="text-center">
              <h1 class="text-danger">Error al cargar receptores</h1>
              <p>Ocurrió un problema al consultar la base de datos.</p>
              <button onclick="window.location.href='/'" class="btn btn-danger mt-3">Volver al inicio</button>
            </div>
          </body>
          </html>
        `);
      }

      res.json({ donadores, receptores });
    });
  });
});

//Reportes
app.get('/descargar-reportes', requireLogin, requireRole('Admin','Medico', 'Inspector'), (req, res) => {
  res.sendFile(__dirname + '/public/reportes.html');
});

app.get('/download-donadores', requireLogin, requireRole('Admin', 'Medico', 'Inspector'), (req, res) => {
  const sql = `SELECT * FROM donadores`;
  connection.query(sql, (err, results) => {
    if (err) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head><meta charset="UTF-8"><title>Error</title>
        <link rel="stylesheet" href="/bootstrap/bootstrap.min.css"></head>
        <body class="container mt-5">
          <div class="alert alert-danger text-center" role="alert">
            <h4 class="alert-heading">Error</h4>
            <p>Error al generar el reporte de donadores.</p>
            <hr>
            <a href="/subir-reportes" class="btn btn-dark">Volver</a>
          </div>
        </body>
        </html>
      `);
    }

    const worksheet = xlsx.utils.json_to_sheet(results);
    const workbook = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(workbook, worksheet, 'Donadores');

    const filePath = path.join(__dirname, 'uploads', 'donadores.xlsx');
    xlsx.writeFile(workbook, filePath);
    res.download(filePath, 'donadores.xlsx');
  });
});

app.get('/download-receptores', requireLogin, requireRole('Admin', 'Medico', 'Inspector'), (req, res) => {
  const sql = `SELECT * FROM receptores`;
  connection.query(sql, (err, results) => {
    if (err) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head><meta charset="UTF-8"><title>Error</title>
        <link rel="stylesheet" href="/bootstrap/bootstrap.min.css"></head>
        <body class="container mt-5">
          <div class="alert alert-danger text-center" role="alert">
            <h4 class="alert-heading">Error</h4>
            <p>Error al generar el reporte de receptores.</p>
            <hr>
            <a href="/subir-reportes" class="btn btn-dark">Volver</a>
          </div>
        </body>
        </html>
      `);
    }

    const worksheet = xlsx.utils.json_to_sheet(results);
    const workbook = xlsx.utils.book_new();
    xlsx.utils.book_append_sheet(workbook, worksheet, 'Receptores');

    const filePath = path.join(__dirname, 'uploads', 'receptores.xlsx');
    xlsx.writeFile(workbook, filePath);
    res.download(filePath, 'receptores.xlsx');
  });
});

//Compatibilidad
app.get('/buscar-match', requireLogin, requireRole('Admin','Medico','Inspector'), (req, res) => {
  const raw = req.query.query?.trim();
  if (!raw) return res.json([]);


  const clean = raw.replace(/[^\w\s]/gi, '').trim();
  const parts = clean.split(/\s+/);

  let sql = 'SELECT tipo, rh FROM receptores WHERE';
  const params = [];

  if (parts.length === 1) {
    
    if (!isNaN(parts[0])) {
      sql += ' id = ?';
      params.push(parts[0]);
    } else {
      sql += ' nombre LIKE ?';
      params.push(`%${parts[0]}%`);
    }
  } else {
    
    const idPart = parts.find(p => !isNaN(p));
    const namePart = parts.filter(p => isNaN(p)).join(' ');
    if (idPart && namePart) {
      sql += ' id = ? AND nombre LIKE ?';
      params.push(idPart, `%${namePart}%`);
    } else if (idPart) {
      sql += ' id = ?';
      params.push(idPart);
    } else {
      sql += ' nombre LIKE ?';
      params.push(`%${namePart}%`);
    }
  }

  connection.query(sql + ' LIMIT 1', params, (err, receptores) => {
    if (err || receptores.length === 0) return res.json([]);

    const { tipo, rh } = receptores[0];
    connection.query(
      'SELECT nombre, edad, peso, tipo, rh FROM donadores WHERE tipo = ? AND rh = ?',
      [tipo, rh],
      (err2, donadores) => {
        if (err2) return res.json([]);
        res.json(donadores);
      }
    );
  });
});

// Ver donadores
app.get('/ver-donadores', requireLogin, requireRole('Admin','Medico'), (req, res) => {
  connection.query('SELECT * FROM donadores', (err, results) => {
    if (err) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head>
          <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Error</title>
          <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
        </head>
        <body class="bg-light">
          <div class="container d-flex justify-content-center align-items-center vh-100">
            <div class="text-center">
              <h1 class="text-danger">Error al cargar donadores</h1>
              <button onclick="window.location.href='/'" class="btn btn-danger mt-3">Volver</button>
            </div>
          </div>
        </body>
        </html>
      `);
    }

    const optionsTipo = (sel) => `
      <select name="tipo" class="form-select form-select-sm me-2" required>
        <option value="O" ${sel==='O'?'selected':''}>O</option>
        <option value="A" ${sel==='A'?'selected':''}>A</option>
        <option value="B" ${sel==='B'?'selected':''}>B</option>
        <option value="AB" ${sel==='AB'?'selected':''}>AB</option>
      </select>
    `;
    const optionsRh = (sel) => `
      <select name="rh" class="form-select form-select-sm me-2" required>
        <option value="+" ${sel==='+'?'selected':''}>+</option>
        <option value="-" ${sel==='-'?'selected':''}>-</option>
      </select>
    `;

    const rows = results.map(d => `
      <tr>
        <td>${d.id}</td>
        <td>${d.nombre}</td>
        <td>${d.edad}</td>
        <td>${d.peso}</td>
        <td>
          <form method="POST" action="/actualizar-donador" class="d-flex align-items-center gap-2">
            <input type="hidden" name="id" value="${d.id}">
            ${optionsTipo(d.tipo)}
            ${optionsRh(d.rh)}
            <button type="submit" class="btn btn-sm btn-success">Actualizar</button>
          </form>
        </td>
        <td>
          <form method="POST" action="/eliminar-donador" onsubmit="return confirm('¿Seguro que deseas eliminar este donador?');">
            <input type="hidden" name="id" value="${d.id}">
            <button type="submit" class="btn btn-sm btn-danger">Eliminar</button>
          </form>
        </td>
      </tr>
    `).join('');

    res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Gestionar Donadores</title>
        <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
      </head>
      <body class="bg-light">
        <div class="container mt-4">
          <h1 class="text-primary mb-3">Gestionar donadores</h1>
          <div class="table-responsive">
            <table class="table table-striped table-hover align-middle">
              <thead class="table-primary">
                <tr>
                  <th>ID</th><th>Nombre</th><th>Edad</th><th>Peso</th><th>Tipo/Rh</th><th>Acciones</th>
                </tr>
              </thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
          <div class="mt-3">
            <button onclick="window.location.href='/'" class="btn btn-outline-primary">Volver al inicio</button>
          </div>
        </div>
      </body>
      </html>
    `);
  });
});

// Actualizar donador 
app.post('/actualizar-donador', requireLogin, requireRole('Admin','Medico'), (req, res) => {
  const { id, tipo, rh } = req.body;

  connection.query('UPDATE donadores SET tipo = ?, rh = ? WHERE id = ?', [tipo, rh, id], (err) => {
    if (err) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head>
          <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Error</title>
          <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
        </head>
        <body class="bg-light">
          <div class="container d-flex justify-content-center align-items-center vh-100">
            <div class="text-center">
              <h1 class="text-danger">Error al actualizar donador</h1>
              <button onclick="window.location.href='/ver-donadores'" class="btn btn-danger mt-3">Volver</button>
            </div>
          </div>
        </body></html>
      `);
    }

    res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Confirmación</title>
        <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
      </head>
      <body class="bg-light">
        <div class="container d-flex justify-content-center align-items-center vh-100">
          <div class="text-center">
            <h1 class="text-success">Donador actualizado correctamente</h1>
            <button onclick="window.location.href='/ver-donadores'" class="btn btn-success mt-3">Volver</button>
          </div>
        </div>
      </body></html>
    `);
  });
});

// Eliminar donador 
app.post('/eliminar-donador', requireLogin, requireRole('Admin','Medico'), (req, res) => {
  const { id } = req.body;

  connection.query('DELETE FROM donadores WHERE id = ?', [id], (err) => {
    if (err) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head>
          <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Error</title>
          <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
        </head>
        <body class="bg-light">
          <div class="container d-flex justify-content-center align-items-center vh-100">
            <div class="text-center">
              <h1 class="text-danger">Error al eliminar donador</h1>
              <button onclick="window.location.href='/ver-donadores'" class="btn btn-danger mt-3">Volver</button>
            </div>
          </div>
        </body></html>
      `);
    }

    res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Confirmación</title>
        <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
      </head>
      <body class="bg-light">
        <div class="container d-flex justify-content-center align-items-center vh-100">
          <div class="text-center">
            <h1 class="text-success">Donador eliminado correctamente</h1>
            <button onclick="window.location.href='/ver-donadores'" class="btn btn-success mt-3">Volver</button>
          </div>
        </div>
      </body></html>
    `);
  });
});

// Ver receptores
app.get('/ver-receptores', requireLogin, requireRole('Admin','Medico'), (req, res) => {
  connection.query('SELECT * FROM receptores', (err, results) => {
    if (err) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head>
          <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Error</title>
          <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
        </head>
        <body class="bg-light">
          <div class="container d-flex justify-content-center align-items-center vh-100">
            <div class="text-center">
              <h1 class="text-danger">Error al cargar receptores</h1>
              <button onclick="window.location.href='/'" class="btn btn-danger mt-3">Volver</button>
            </div>
          </div>
        </body>
        </html>
      `);
    }

    const optionsTipo = (sel) => `
      <select name="tipo" class="form-select form-select-sm me-2" required>
        <option value="O" ${sel==='O'?'selected':''}>O</option>
        <option value="A" ${sel==='A'?'selected':''}>A</option>
        <option value="B" ${sel==='B'?'selected':''}>B</option>
        <option value="AB" ${sel==='AB'?'selected':''}>AB</option>
      </select>
    `;
    const optionsRh = (sel) => `
      <select name="rh" class="form-select form-select-sm me-2" required>
        <option value="+" ${sel==='+'?'selected':''}>+</option>
        <option value="-" ${sel==='-'?'selected':''}>-</option>
      </select>
    `;

    const rows = results.map(r => `
      <tr>
        <td>${r.id}</td>
        <td>${r.nombre}</td>
        <td>${r.edad}</td>
        <td>${r.peso}</td>
        <td>
          <form method="POST" action="/actualizar-receptor" class="d-flex align-items-center gap-2">
            <input type="hidden" name="id" value="${r.id}">
            ${optionsTipo(r.tipo)}
            ${optionsRh(r.rh)}
            <button type="submit" class="btn btn-sm btn-success">Actualizar</button>
          </form>
        </td>
        <td>
          <form method="POST" action="/eliminar-receptor" onsubmit="return confirm('¿Seguro que deseas eliminar este receptor?');">
            <input type="hidden" name="id" value="${r.id}">
            <button type="submit" class="btn btn-sm btn-danger">Eliminar</button>
          </form>
        </td>
      </tr>
    `).join('');

    res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Gestionar Receptores</title>
        <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
      </head>
      <body class="bg-light">
        <div class="container mt-4">
          <h1 class="text-primary mb-3">Gestionar receptores</h1>
          <div class="table-responsive">
            <table class="table table-striped table-hover align-middle">
              <thead class="table-primary">
                <tr>
                  <th>ID</th><th>Nombre</th><th>Edad</th><th>Peso</th><th>Tipo/Rh</th><th>Acciones</th>
                </tr>
              </thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
          <div class="mt-3">
            <button onclick="window.location.href='/'" class="btn btn-outline-primary">Volver al inicio</button>
          </div>
        </div>
      </body>
      </html>
    `);
  });
});

// Actualizar receptor 
app.post('/actualizar-receptor', requireLogin, requireRole('Admin','Medico'), (req, res) => {
  const { id, tipo, rh } = req.body;

  connection.query('UPDATE receptores SET tipo = ?, rh = ? WHERE id = ?', [tipo, rh, id], (err) => {
    if (err) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head>
          <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Error</title>
          <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
        </head>
        <body class="bg-light">
          <div class="container d-flex justify-content-center align-items-center vh-100">
            <div class="text-center">
              <h1 class="text-danger">Error al actualizar receptor</h1>
              <button onclick="window.location.href='/ver-receptores'" class="btn btn-danger mt-3">Volver</button>
            </div>
          </div>
        </body></html>
      `);
    }

    res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Confirmación</title>
        <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
      </head>
      <body class="bg-light">
        <div class="container d-flex justify-content-center align-items-center vh-100">
          <div class="text-center">
            <h1 class="text-success">Receptor actualizado correctamente</h1>
            <button onclick="window.location.href='/ver-receptores'" class="btn btn-success mt-3">Volver</button>
          </div>
        </div>
      </body></html>
    `);
  });
});

// Eliminar receptor 
app.post('/eliminar-receptor', requireLogin, requireRole('Admin','Medico'), (req, res) => {
  const { id } = req.body;

  connection.query('DELETE FROM receptores WHERE id = ?', [id], (err) => {
    if (err) {
      return res.send(`
        <!DOCTYPE html>
        <html lang="es">
        <head>
          <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
          <title>Error</title>
          <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
        </head>
        <body class="bg-light">
          <div class="container d-flex justify-content-center align-items-center vh-100">
            <div class="text-center">
              <h1 class="text-danger">Error al eliminar receptor</h1>
              <button onclick="window.location.href='/ver-receptores'" class="btn btn-danger mt-3">Volver</button>
            </div>
          </div>
        </body></html>
      `);
    }

    res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Confirmación</title>
        <link rel="stylesheet" href="/bootstrap/bootstrap.min.css">
      </head>
      <body class="bg-light">
        <div class="container d-flex justify-content-center align-items-center vh-100">
          <div class="text-center">
            <h1 class="text-success">Receptor eliminado correctamente</h1>
            <button onclick="window.location.href='/ver-receptores'" class="btn btn-success mt-3">Volver</button>
          </div>
        </div>
      </body></html>
    `);
  });
});

// Iniciar el servidor
app.listen(3000, () => {
  console.log('Servidor corriendo en http://localhost:3000');

});
