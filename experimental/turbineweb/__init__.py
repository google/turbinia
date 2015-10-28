from flask import Flask

from models import configure_engine
from models import init_db
from views import turbineweb_views


def create_app():
    """Create the Flask app instance that is used throughout the application.
    Returns:
        Application object (instance of flask.Flask).
    """
    # Setup the Flask app and load the config.
    app = Flask(__name__)
    app.config[u'DEBUG'] = True
    app.config[u'SQLALCHEMY_DATABASE_URI'] = u''

    # Setup the database.
    configure_engine(app.config[u'SQLALCHEMY_DATABASE_URI'])
    init_db()

    # Register blueprints. Blueprints are a way to organize Flask applications.
    # For more information: http://flask.pocoo.org/docs/latest/blueprints/
    app.register_blueprint(turbineweb_views)

    # Setup CSRF protection for the whole application
    CsrfProtect(app)

    return app
