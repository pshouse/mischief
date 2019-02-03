import toga
import os
from durus.connection import Connection
from durus.file_storage import FileStorage
from urllib.parse import quote
from toga.style import Pack

class MsfWindow(toga.Window):
    def __init__(self, msf):
        self.msf = msf
        title = os.path.splitext(os.path.basename(msf.filename))[0]

        super().__init__(
            title=title,
            position=(200,200),
            size=(984, 576),
            closeable=True
        )
        self.create()

    def create(self):
        self.html_view = toga.WebView(
            style=Pack(
                flex=1,
                width=984,
                height=576
            ),
            #on_key_down=self.msf.on_key_press
        )
        self.content = self.html_view
    
    def on_close(self):
        self.msf.close()

    def redraw(self):
        pass
        #self.html_view.set_content(self.msf.fileURL, b'test content')
        
class MSF(toga.Document):
    db = None

    def __init__(self, filename, app):
        super().__init__(filename=filename, document_type='Mschf Storage Facility', app=app)
        self.window = MsfWindow(self)
        self.window.app = self.app

    def read(self):
        if os.path.isfile(self.filename):
            self.db = Connection(FileStorage(self.filename))
    
    def show(self):
        self.window.redraw()
        self.window.show()

    def fileURL(self):
        return 'file://{}'.format(quote(self.filename))
    
    def close(self):
        print('closing')