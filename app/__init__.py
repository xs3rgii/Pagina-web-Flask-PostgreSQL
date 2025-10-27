from flask import Flask

def create_app():
    app = Flask(__name__)
    app.secret_key = "CAMBIALO_POR_UNA_CLAVE_SEGURA"

    from .routes import main
    app.register_blueprint(main)

    return app
