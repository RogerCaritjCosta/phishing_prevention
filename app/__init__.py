import os
from flask import Flask
from flask_cors import CORS


def create_app():
    app = Flask(
        __name__,
        static_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "static"),
        template_folder=os.path.join(os.path.dirname(os.path.dirname(__file__)), "templates"),
    )

    app.config.from_object("app.config.Config")
    CORS(app)

    from app.api import api_bp
    app.register_blueprint(api_bp, url_prefix="/api/v1")

    @app.route("/")
    def index():
        from flask import render_template
        return render_template("index.html")

    return app
