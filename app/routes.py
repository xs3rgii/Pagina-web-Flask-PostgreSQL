from flask import Blueprint, render_template, request, redirect, url_for, session, flash
import psycopg2
from psycopg2 import pool, sql # sql se mantiene para mostrar el contraste, pero NO se usa en la ruta vulnerable
from contextlib import contextmanager
import re
from functools import wraps

# -------------------------
# Declaración del Blueprint
# -------------------------
main = Blueprint('main', __name__)

# Pool de conexiones (opcional, para mejor rendimiento)
connection_pool = None

# -------------------------
# UTILIDADES
# -------------------------
def init_pool(host, port, dbname, user, password, minconn=1, maxconn=5):
    """Inicializa el pool de conexiones"""
    global connection_pool
    try:
        connection_pool = psycopg2.pool.SimpleConnectionPool(
            minconn, maxconn,
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password
        )
        return True
    except Exception:
        # Nota: Si falla la inicialización, el código usará conexiones directas
        return False

@contextmanager
def get_db_connection():
    """Context manager para manejar conexiones del pool"""
    conn = None
    try:
        if connection_pool:
            conn = connection_pool.getconn()
        else:
            cfg = session.get('db_config')
            if cfg:
                conn = psycopg2.connect(**cfg)
        yield conn
    finally:
        if conn:
            if connection_pool:
                connection_pool.putconn(conn)
            else:
                conn.close()

def login_required(f):
    """Decorador para proteger rutas que requieren autenticación"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'db_config' not in session:
            flash("Debe iniciar sesión para acceder a esta página.")
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function

def parse_db_error(error, dbname=None, user=None):
    """Parsea errores de PostgreSQL y retorna mensaje específico"""
    msg = str(error).lower()
    
    # Servidor no disponible
    if "could not connect to server" in msg or "connection refused" in msg or \
       "no route to host" in msg or "network is unreachable" in msg or \
       "timeout" in msg or "timed out" in msg:
        return "El servidor no está disponible o no es accesible."
    
    # Base de datos incorrecta
    if ("database" in msg and "does not exist" in msg) or ("no existe la base de datos" in msg):
        return f"La base de datos '{dbname}' no existe." if dbname else "La base de datos no existe."
    
    # Usuario incorrecto - Verificar primero si menciona explícitamente el rol
    if ("role" in msg and "does not exist" in msg) or \
       ("el rol" in msg and "no existe" in msg):
        return f"El usuario '{user}' no existe." if user else "El usuario no existe."
    
    # Contraseña incorrecta O usuario incorrecto (PostgreSQL no diferencia por seguridad)
    if "password authentication failed" in msg or \
       "authentication failed" in msg or \
       "la autentificación password falló" in msg:
        return "El usuario o la contraseña son incorrectos."
    
    # Error genérico (sin mostrar detalles del servidor)
    return "Error de conexión. Verifica los datos ingresados."

# -------------------------
# LOGIN
# -------------------------
@main.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        session.clear()
        return render_template('login.html')

    # POST request
    dbname = request.form.get('dbname', '').strip()
    user = request.form.get('user', '').strip()
    password = request.form.get('password', '').strip()
    host = request.form.get('host', '192.168.122.159').strip()
    port = request.form.get('port', '5432')

    # Validación de campos
    if not all([dbname, user, password]):
        flash("Todos los campos son obligatorios.")
        return render_template('login.html')

    # Validación de puerto
    try:
        port = int(port)
    except ValueError:
        flash("El puerto debe ser un número válido.")
        return render_template('login.html')

    try:
        # Probar conexión con validación completa
        conn = psycopg2.connect(
            host=host,
            port=port,
            dbname=dbname,
            user=user,
            password=password,
            connect_timeout=5  # Timeout de 5 segundos
        )
        
        # Verificar que la conexión realmente funciona
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()

        # Guardar configuración en sesión
        session['db_config'] = {
            'host': host,
            'port': port,
            'dbname': dbname,
            'user': user,
            'password': password
        }
        session.permanent = True
        
        flash(f"Conectado exitosamente a '{dbname}'.", "success")
        return redirect(url_for('main.mostrar_tablas'))

    except psycopg2.OperationalError as e:
        # Errores relacionados con la conexión, autenticación, BD, usuario
        error_msg = parse_db_error(e, dbname, user)
        flash(error_msg, "error")
        return render_template('login.html')
    
    except psycopg2.Error as e:
        # Otros errores de PostgreSQL
        flash(f"Error de PostgreSQL: {str(e)}", "error")
        return render_template('login.html')

    except Exception as e:
        # Errores inesperados
        flash(f"Error inesperado: {str(e)}", "error")
        return render_template('login.html')

# -------------------------
# MOSTRAR TABLAS (Seguro: No acepta entrada del usuario para el SQL)
# -------------------------
@main.route('/tablas')
@login_required
def mostrar_tablas():
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                # Consulta segura y fija
                cur.execute("""
                    SELECT table_name
                    FROM information_schema.tables
                    WHERE table_type = 'BASE TABLE' 
                      AND table_schema = 'public'
                    ORDER BY table_name
                """)
                tables = [row[0] for row in cur.fetchall()]
        
        return render_template('tablas.html', tables=tables)
    
    except Exception as e:
        flash(f"Error al listar tablas: {e}", "error")
        return redirect(url_for('main.login'))

# -------------------------
# VER DATOS DE UNA TABLA (VULNERABLE A SQL INJECTION) 🚨
# -------------------------
@main.route('/tabla/<tabla>')
@login_required
def ver_tabla(tabla):
    
    # 🛑 ATENCIÓN: Esta función es deliberadamente VULNERABLE.
    # El valor de la URL 'tabla' se inserta directamente en la consulta SQL.
    
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cur:
                
                # VULNERABLE: Usando f-string para construir la consulta.
                # Un atacante puede cerrar las comillas e inyectar código.
                cur.execute(f'SELECT * FROM {tabla} LIMIT 100')
                
                filas = cur.fetchall()
                columnas = [desc[0] for desc in cur.description]
        
        return render_template('tabla_datos.html', 
                             tabla=tabla, 
                             columnas=columnas, 
                             filas=filas)
    
    except psycopg2.ProgrammingError as e:
        # Este error puede ocurrir si la inyección resulta en sintaxis SQL inválida
        flash(f"Error de programación SQL (posible intento de inyección): {e}", "error")
        return redirect(url_for('main.mostrar_tablas'))
    
    except psycopg2.Error as e:
        flash(f"Error al leer la tabla: {e}", "error")
        return redirect(url_for('main.mostrar_tablas'))
    
    except Exception as e:
        flash("Error inesperado.", "error")
        return redirect(url_for('main.mostrar_tablas'))

# -------------------------
# CERRAR SESIÓN
# -------------------------
@main.route('/logout')
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "success")
    return redirect(url_for('main.login'))

# -------------------------
# NOTA DE SEGURIDAD
# -------------------------
# Para hacer este código seguro, la línea
# cur.execute(f'SELECT * FROM "{tabla}" LIMIT 100')
# debería ser reemplazada por:
# query = sql.SQL("SELECT * FROM {table} LIMIT 100").format(table=sql.Identifier(tabla))
# cur.execute(query)
