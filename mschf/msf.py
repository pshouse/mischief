import toga
import os
from durus.connection import Connection

class MSF(toga.Document):
    def __init__(self, filename, app):
        super().__init__(filename=filename, document_type='Mschf Storage Facility', app=app)
    
    def read(self):
        if os.path.isfile(self.filename):
            self.app.open_db(self.filename)