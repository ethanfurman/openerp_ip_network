# -*- coding: utf-8 -*-

# curl -s 127.0.0.1:8069/ip_network/upload/ --data ip=... --data-binary=@<filename> -H "Content-Type:application/octet-stream"

import logging
import werkzeug
from antipathy import Path
from dbf import DateTime
from mimetypes import guess_type
from openerp import ROOT_DIR
from openerp.addons.web.http import Controller, httprequest
from openerp.addons.web.controllers.main import content_disposition
from operator import div
from scription import OrmFile

_logger = logging.getLogger(__name__)
ROOT_DIR = Path(ROOT_DIR)
CONFIG = ROOT_DIR / 'config/fnx.ini'
FILES = ROOT_DIR / 'var/openerp/fnxfs/ip_network/screenshot'

config = OrmFile(CONFIG)
database = config.openerp.db
password = config.openerp.pw
login = config.openerp.user

class ScreenShot(Controller):

    _cp_path = Path('/ip_network/screenshot')

    @httprequest
    def upload(self, request):
        "accepts a new screenshot, along with the IP address to save it to"
        request.session.authenticate(database, login, password)
        data = request.httprequest.data
        if data.startswith('ip='):
            ip, image = data.split('&', 1)
        else:
            image, ip = data.rsplit('&', 1)
        ip = ip[3:]
        if image[:4] == '\xff\xd8\xff\xe0' and image[6:10] == 'JFIF':
            ext = '.jpg'
        elif image[1:4] == 'PNG':
            ext = '.png'
        else:
            ext = '.img'
        if not image:
            return werkzeug.exceptions.BadRequest('image file is empty')
        nd = request.session.model('ip_network.device')
        dev_ids = nd.search([('ip_addr','=',ip)])
        if not dev_ids:
            return request.not_found('no device with IP %s' % ip)
        dev_id = dev_ids[0]
        #
        # save file
        perms, (root, trunk, branch, leaf) = nd.fnxfs_field_info(dev_id, 'screenshots')
        target_path= reduce(div, [p for p in [root, trunk, branch] if p])
        target_path /= leaf
        target_file = DateTime.now().strftime('%Y-%m-%d_%H:%M:%S') + ext
        if not target_path.exists():
            target_path.mkdir()
        with (target_path / target_file).open('wb') as target_path_file:
            target_path_file.write(image)
        #
        # create record
        ns = request.session.model('ip_network.device.screenshot')
        ns.create({'name':target_file, 'device_id':dev_id})
        #
        # done
        return "screenshot for %s successfully uploaded\n" % ip

    @httprequest
    def retrieve(self, request, ip, file):
        "returns the requested screenshot"
        request.session.authenticate(database, login, password)
        nd = request.session.model('ip_network.device')
        dev_ids = nd.search([('ip_addr','=',ip)])
        if not dev_ids:
            return request.not_found('no device with IP %s' % ip)
        perms, (root, trunk, branch, leaf) = nd.fnxfs_field_info(dev_ids[0], 'screenshots')
        target_path = reduce(div, [p for p in [root, trunk, branch] if p])
        target_path /= leaf
        target_path_file = target_path / file
        if not target_path_file.exists():
            return request.not_found('screenshot %s for %s does not exists' % (file, ip))
        try:
            with (target_path_file).open('rb') as fh:
                file_data = fh.read()
            return request.make_response(
                    file_data,
                    headers=[
                        ('Content-Disposition',  content_disposition(file, request)),
                        ('Content-Type', guess_type(file)[0] or 'octet-stream'),
                        ('Content-Length', len(file_data)),
                        ],
                    )
        except Exception:
            _logger.exception('error accessing %r', file)
            return werkzeug.exceptions.InternalServerError(
                    'An error occured attempting to access %r; please let IT know.'
                    % (str(file),))

