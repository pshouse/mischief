import toga
from toga.style import Pack
from toga.style.pack import COLUMN, ROW
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.protocol import Protocol, Factory
from twisted.internet import reactor
from twisted.internet.endpoints import TCP4ClientEndpoint, connectProtocol
from uuid import uuid4
import json
import logging
import sys 
from datetime import datetime, timedelta
import pytz

if __name__ == '__main__':
    from gen_cert import generate_selfsigned_cert, x509, NameOID, default_backend, serialization, hashes
    from durus.file_storage import FileStorage
    from durus.connection import Connection
    from durus.persistent import Persistent
else:
    from mschf.durus.file_storage import FileStorage
    from mschf.durus.connection import Connection
    from mschf.durus.persistent import Persistent
    from mschf.gen_cert import generate_selfsigned_cert, x509, NameOID, default_backend, serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import utils
import os.path
import toml
from datetime import datetime, timedelta
from dataclasses import dataclass
DEFAULT_TZ_NAME = 'America/New_York'

# msf = Mschf Storage Facility
FILE_EXT = ".msf"

DEFAULT_DB_FILE = "lil" + FILE_EXT

SETTINGS_FILE = 'settings.toml'

settings = {
    'tz_name': DEFAULT_TZ_NAME,
    'db_file': DEFAULT_DB_FILE,
    'user_id': 'ca.crt'
}

db = None

import socket
host_name = socket.gethostname()

log = logging.getLogger(__name__)
out_hdlr = logging.StreamHandler(sys.stdout)
out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
out_hdlr.setLevel(logging.INFO)
log.addHandler(out_hdlr)
log.setLevel(logging.INFO)

generate_node_id = lambda: str(uuid4())

def load_settings(settings):
    if not os.path.isfile(SETTINGS_FILE):
        with open(SETTINGS_FILE, 'w') as f:
            toml.dump(settings, f)
    else:
        settings = toml.loads(SETTINGS_FILE)
    
def start_server():
    log.info('Startng server . . . ')
    endpoint = TCP4ServerEndpoint(reactor, 5999)
    endpoint.listen(MFactory())

class Mschf(toga.App):
    def startup(self):
        log.info("We're running on {}".format(host_name))
        log.info("Loading settings from {}".format(SETTINGS_FILE))
        load_settings(settings)

        tzinfo = pytz.timezone(settings['tz_name'])
        log.info("Time zone is {}".format(tzinfo))
        
        if not os.path.isfile(settings['user_id']):
            pem_cert, pem_key = generate_selfsigned_cert(host_name)
            with open('ca.crt','wb') as f:
                f.write(pem_cert)
            with open('ca.key','wb') as f:
                f.write(pem_key)
        else:
            pem_cert = open('ca.crt','rb').read()
        cert = x509.load_pem_x509_certificate(pem_cert,default_backend())
        log.info("User CN={}".format(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value))

        #@dataclass
        class M(Persistent, object):
            created_at: datetime = None
#
        #class Meta(M):
        #    pass

        #class Data(M):
        #    def __init__(self, *args, **kwargs):            
        #        self.created_at = tzinfo.localize(datetime.now())
        #        self.modified_at = self.created_at
        
        def open_db(path_to_msf):
            connection = Connection(FileStorage(path_to_msf))
            return connection

        #log.info('root: {}'.format(root.data))
        db = open_db(settings['db_file'])
        log.info('{}'.format(db))
        db_root = db.get_root()
        #log.info('{}'.format(len(db_root)))

        if len(db_root) == 0:
            # empty MSF
            #about = {}
            #about = dict({'created_at':tzinfo.localize(datetime.now()).isoformat()})
            about = M(tzinfo.localize(datetime.now()))
            #about.created_at = 
            log.info('{}'.format(about))
            #about.update({'created_by_cert' : cert.public_bytes(serialization.Encoding.PEM)})
            about.created_by_cert = cert.public_bytes(serialization.Encoding.PEM)
            #about.update({'uuid' : uuid4()})
            about.uuid = uuid4()
            #about.update({"title" : 'About'})
            about.title = 'About'
            #about.update({"title" : 'About'})
            about.body = '''
                About this mouse
            '''
            db_root['about'] = about
            
            from durus.persistent_list import PersistentList
            from durus.persistent_dict import PersistentDict
            acl = PersistentDict()
            acl['default'] = None
            
            db_root['acl'] = acl
             
            db.commit()
        else:
            acl = db_root['acl']

        #log.inf('{}'.format())
        log.info('about: {}'.format(db_root['about']))

        #start_server()
        log.info('Startng server . . . ')
        endpoint = TCP4ServerEndpoint(reactor, 5999)
        m_factory = MFactory()
        endpoint.listen(m_factory)
        
        def gotProtocol(p):
            """The callback to start the protocol exchange. We let connecting
            nodes start the hello handshake""" 
            p.send_hello()

        point = TCP4ClientEndpoint(reactor, "localhost", 5999)
        d = connectProtocol(point, m_factory)
        d.addCallback(gotProtocol)
        
        # Create a main window with a name matching the app

        self.main_window = toga.MainWindow(title=self.name)

        # Create a main content box
        main_box = toga.Box()

        # Add the content on the main window
        self.main_window.content = main_box

        # Show the main window
        self.main_window.show()

class MProtocol(Protocol):
    def __init__(self, factory):
        self.factory = factory
        self.state = "HELLO"
        self.remote_nodeid = None
        self.nodeid = self.factory.nodeid

    def connectionMade(self):
        print( "Connection from", self.transport.getPeer())

        def connectionLost(self, reason):
          if self.remote_nodeid in self.factory.peers:
              self.factory.peers.pop(self.remote_nodeid)
          print( self.nodeid, "disconnected")

    def dataReceived(self, data):
        for line in data.splitlines():
            line = line.strip()
            if self.state == "HELLO":
                self.handle_hello(line)
                self.state = "READY"

    def send_hello(self):
        hello = json.dumps({'nodeid': self.nodeid, 'msgtype': 'hello'})
        self.transport.write(hello + "\n")
   
    def handle_hello(self, hello):
        hello = json.loads(hello)
        self.remote_nodeid = hello["nodeid"]
        if self.remote_nodeid == self.nodeid:
            print("Connected to myself.")
            self.transport.loseConnection()
        else:
            self.factory.peers[self.remote_nodeid] = self

class MFactory(Factory):
    def startFactory(self):
        self.peers = {}
        self.nodeid = generate_node_id()

    def buildProtocol(self, addr):
        return MProtocol(self)
    
def main():
    return Mschf('mschf', 'com.mschf.mschf')

if __name__ == '__main__':
    main().main_loop()