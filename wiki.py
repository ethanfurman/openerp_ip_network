from __future__ import print_function

# imports
from osv import osv
import logging

# config
_logger = logging.getLogger(__name__)
# CONFIG = OrmFile(Path('/%s/fnx.ini' % CONFIG_DIR), types={'_path': Path})
# KNOWN_HOSTS = Path(pwd.getpwnam('openerp')[5]) / '.ssh/known_hosts'
# QUERY_SCRIPT = Path('/opt/bin/ip_network_query')
# VIRTUAL_ENV = Path(os.environ.get('VIRTUAL_ENV'))
# WS_SCRIPT_LOCATION = VIRTUAL_ENV / 'ws' /'bin'
# WS_SCRIPTS = {}

class ip_network_wiki(osv.Model):
    "IP Network Wiki"
    _name = 'ip_network.wiki'
    _inherit = 'wiki.page'
    _description = 'IP Network Wiki Page'

    _defaults = {
            'wiki_key': 'IP-Network',
            }
