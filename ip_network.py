from __future__ import print_function

# imports
from antipathy import Path
from ast import literal_eval
from dbf import DateTime, Time
from VSS.utils import translator
from fnx_fs.fields import files
from fnx.oe import Normalize
from openerp import CONFIG_DIR, SUPERUSER_ID
from openerp.osv.orm import except_orm as ValidateError
from openerp.exceptions import ERPError
from openerp.tools import DEFAULT_SERVER_DATE_FORMAT, DEFAULT_SERVER_DATETIME_FORMAT, SERVER_TIMEZONE, UTC
from openerp.tools import self_ids, NamedLock, stonemark2html
from operator import div
from osv import orm, osv, fields
from psycopg2 import ProgrammingError
from scription import Execute, Job, OrmFile, Var
from VSS.finance import FederalHoliday
from xaml import Xaml
import images
import logging
import openerp
import os
import pwd
import re
import textwrap
import threading
import traceback

# config
_logger = logging.getLogger(__name__)
CONFIG = OrmFile(Path('/%s/fnx.ini' % CONFIG_DIR), types={'_path': Path})
KNOWN_HOSTS = Path(pwd.getpwnam('openerp')[5]) / '.ssh/known_hosts'
QUERY_SCRIPT = Path('/opt/bin/ip_network_query')
VIRTUAL_ENV = Path(os.environ.get('VIRTUAL_ENV'))
WS_SCRIPT_LOCATION = VIRTUAL_ENV / 'ws' /'bin'
WS_SCRIPTS = {}

NamedLock = NamedLock()

class FieldType(fields.SelectionEnum):
    _order_ = 'boolean char date datetime float html integer other text time'
    _init_ = 'db user type'
    #
    boolean = 'Boolean', fields.boolean
    char = 'Character', fields.char
    date = 'Date', fields.date
    datetime = 'Date Time', fields.datetime
    float = 'Float', fields.float
    html = 'HTML', fields.html
    integer = 'Integer', fields.integer
    other = 'Other', None
    text = 'Text', fields.html
    time = 'Time', fields.float
    #
    def __new__(cls, db, user, type):
        obj = fields.SelectionEnum.__new_member__(cls, db, user)
        obj.type = type
        return obj

class TestWhere(fields.SelectionEnum):
    _order_ = 'ssh local user'
    ssh = 'SSH'
    local = 'Local'
    user = 'User Entry'

class DeviceStatus(fields.SelectionEnum):
    _order_ = 'online great good warning danger offline unknown retired'
    online = 'On-line'
    great = 'Great'
    good = 'Good'
    warning = 'Warning'
    danger = 'Fix!'
    offline = 'Off-line'
    unknown = 'Unknown (tar-pit?)'
    retired = 'Out of Service'
ONLINE, GREAT, GOOD, WARNING, DANGER, OFFLINE, UNKNOWN, RETIRED = DeviceStatus

class DeviceTypeSource(fields.SelectionEnum):
    _order_ = 'user system'
    user = "User controlled"
    system = "System controlled"

class JobFrequency(fields.SelectionEnum):
    _order_ = 'continuous intermittent daily weekly monthly quarterly yearly urgent'
    continuous = "multiple times per hour"
    intermittent = "multiple times per day"
    daily = "once a day jobs"
    weekly = "once a week jobs"
    monthly = "once a month jobs"
    quarterly = "once a quarter jobs"
    yearly = "once a year jobs"
    urgent = "single event occurance (store value for trip, alert, and clear)"
CONTINUOUS, INTERMITTENT, DAILY, WEEKLY, MONTHLY, QUARTERLY, YEARLY, URGENT = JobFrequency
JF = JobFrequency

class JobStatus(fields.SelectionEnum):
    _order_ = 'normal overdue failed sleeping historical'
    normal = 'Waiting for next beat.'
    overdue = 'Next beat is overdue.'
    failed = 'Job has failed.'
    sleeping = 'Temporarily suspended.'
    historical = "no longer running"
NORMAL, OVERDUE, FAILED, SUSPENDED, HISTORICAL = JobStatus

class BeatAction(fields.SelectionEnum):
    _order_ = 'ping alert trip clear'
    ping = 'record beat'
    alert = 'notify priority job has failed'
    trip = 'record that priority job has failed'
    clear = 'clear priority job failure'
PING, ALERT, TRIP, CLEAR = BeatAction

# helpers

def _ip2int(module, cr, uid, ids, field_name, arg, context):
    res = {}
    for device_rec in module.read(cr, uid, ids, fields=['id','ip_addr'], context=context):
        ip_addr = device_rec['ip_addr']
        quads = ip_addr.split('.')
        if len(quads) != 4:
             raise ERPError('bad ip address', 'ip address should be a dotted quad [got %r]' % (ip_addr, ))
        try:
            quads = map(int, quads)
            if not all([0 <= q <= 255 for q in quads]):
                raise ValueError
        except ValueError:
            raise ERPError('bad ip address', 'quad values should be between 0 - 255 [got %r]' % (ip_addr, ))
        ip_as_int = (quads[0] << 24) + (quads[1] << 16) + (quads[2] << 8) + quads[3]
        res[device_rec['id']] = '%010d' % ip_as_int
    return res

# Tables

class network(osv.Model):
    "each record is a network to monitor"
    _name = 'ip_network.network'

    _columns = {
        'name': fields.char('Name', size=64),
        'network': fields.char('Network', size=18, help='xxx.xxx.xxx.xxx/nn'),
        'description': fields.text('Description'),
        }


class device_type(Normalize, osv.Model):
    "possible type that a device can be"
    _name = 'ip_network.device.type'
    _order = 'sequence'

    _columns = {
        'name': fields.char('Device Type', size=64, required=True),
        'short_name': fields.char('Short Name', size=24, required=True, help='letters, numbers, and underscores only'),
        'description': fields.text(),
        'test': fields.char('Test', size=128),
        'sequence': fields.integer('Run Order'),
        }

    _constraints = [
        (lambda s, *a: s.check_unique('name', *a), '\nDevice type already exists', ['name']),
        ]

    _sql_constraints = [
        ('valid_identifier', "CHECK (short_name ~* '[a-z]+[a-z0-9_]*')",  'Invalid name: only lowercase letters, digits, and the _ may be used.'),
        ('identifier_uniq', 'unique(short_name)', 'Short name must be unique.'),
        ]


class device(osv.Model):
    "a physical device with an IP address"
    _name = 'ip_network.device'
    _rec_name = 'ip_addr'
    _order = 'ip_addr_as_int asc'
    _inherit = 'fnx_fs.fs'

    _fnxfs_path = 'ip_network'

    def __init__(self, pool, cr):
        'read extra_test table and add found records to this table'
        cr.execute('SELECT name from ir_model where model=%s', ('ip_network.device', ))
        if cr.fetchone() is not None:
            self._add_extra_field(cr, mode='init')
        return super(device, self).__init__(pool, cr)

    def _add_extra_field(self, cr, extra_fields=None, mode=None):
        "dynamically update _columns with field info in .extra.field"
        # get our own cursor in case something fails
        db_name = threading.current_thread().dbname
        db = openerp.sql_db.db_connect(db_name)
        if not extra_fields:
            # this only runs during startup
            ip_cr = db.cursor()
            try:
                ip_cr.execute('SELECT name, string, type, notes, size FROM ip_network_extra_field')
            except ProgrammingError:
                raise
            else:
                db_fields = ip_cr.dictfetchall()
                extra_fields = []
                for fields_dict in db_fields:
                    extra_fields.append(fields_dict)
            finally:
                ip_cr.close()
        for extra_field in extra_fields:
            name = extra_field['string']
            field_name = extra_field['name']
            # check that field doens't already exist
            if field_name in self._columns:
                if mode == 'init':
                    continue
                raise ERPError('Duplicate Field', 'Field "%s" (%s) already exists' % (name, field_name))
            if mode == 'rename':
                old_field_name = extra_field['old_name']
                self._columns[field_name] = self._columns[old_field_name]
                self._all_columns[field_name] = self._all_columns[old_field_name]
                self._columns[field_name].string = name
                assert self._all_columns[field_name].column.string is name, '_column and _all_column.column are out of sync'
                del self._columns[old_field_name]
                del self._all_columns[old_field_name]
                cr.execute(
                        """ALTER TABLE fnx_quality_assurance """
                        """RENAME %s TO %s""" % (old_field_name, field_name),
                        )
                cr.execute(
                        """UPDATE ir_model_fields """
                        """SET name=%s """
                        """WHERE model='ip_network.device' AND name=%s"""
                        ,
                        (field_name, old_field_name),
                        )
                old_field_name = 'field_' + self._table + '_' + old_field_name
                field_name = 'field_' + self._table + '_' + field_name
                cr.execute(
                        """UPDATE ir_model_data """
                        """SET name=%s """
                        """WHERE model='ir.model.fields' AND name=%s"""
                        ,
                        (field_name, old_field_name),
                        )
            else:
                field_name = extra_field.pop('name')
                field_type = FieldType[extra_field.pop('type')]
                if field_type is not FieldType.char:
                    extra_field.pop('size', None)
                col = field_type.type(**extra_field)._finalize(self.__class__, field_name)
                pg_type = orm.get_pg_type(col)[1]
                self._columns[field_name] = col
                self._all_columns[field_name] = fields.column_info(field_name, col)
                if mode == 'init':
                    # columns updated, postgre tables already correct
                    continue
                cr.execute('ALTER TABLE "%s" ADD COLUMN "%s" %s' % (self._table, field_name, pg_type))

                cr.execute('select nextval(%s)', ('ir_model_fields_id_seq',))
                id = cr.fetchone()[0]
                cr.execute("SELECT id FROM ir_model WHERE model=%s", (self._name,))
                model_id = cr.fetchone()[0]
                cr.execute("""INSERT INTO ir_model_fields (
                    id, model_id, model, name, field_description, ttype,
                    relation, view_load, state, select_level, relation_field, translate, serialization_field_id
                ) VALUES (
                    %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                )""", (
                    id, model_id, self._name, field_name, name, col._type, '', False, 'base', 0, '', False, None,
                ))
                name1 = 'field_' + self._table + '_' + field_name
                cr.execute("INSERT INTO ir_model_data (name,date_init,date_update,module,model,res_id) VALUES (%s, (now() at time zone 'UTC'), (now() at time zone 'UTC'), %s, %s, %s)", \
                    (name1, 'ip_network', 'ir.model.fields', id))


    def _remove_extra_field(self, cr, extra_fields):
        for field_name in extra_fields:
            del self._all_columns[field_name]
            del self._columns[field_name]
            cr.execute('SELECT id FROM ir_model WHERE model=%s', (self._name,))
            model_id = cr.fetchone()[0]
            cr.execute(
                    'SELECT id FROM ir_model_fields WHERE model_id=%s AND model=%s AND name=%s',
                    (model_id, self._name, field_name),
                    )
            res_id = cr.fetchone()[0]
            cr.execute('DELETE FROM ir_model_fields WHERE id=%s', (res_id, ))
            name1 = 'field_' + self._table + '_' + field_name
            cr.execute(
                    '''DELETE FROM ir_model_data WHERE module='ip_network' and model='ir.model.fields' AND name=%s AND res_id=%s''',
                    (name1, res_id),
                    )
            cr.execute('ALTER TABLE %s DROP COLUMN %s' % (self._table, field_name))

    def _get_image(self, cr, uid, ids, field_names, arg, context):
        res = {}
        if ids:
            for device in self.browse(cr, uid, ids, context=context):
                res[device.id] = values = {}
                if device.status is False:
                    for field in field_names:
                        values[field] = False
                    continue
                color = DEVICE_STATUS.get(device.status)
                if color is None:
                    raise ERPError('Error', 'status of %r not recognized' % device.status)
                color = getattr(images, color)
                for field in field_names:
                    values[field] = color[field]
        elif arg:
            color = DEVICE_STATUS.get(device.status)
            if color is None:
                raise ERPError('Error', 'status of %r not recognized' % device.status)
            color = getattr(images, color)
            for field in field_names:
                res[field] = color[field]
        return res

    def _get_host_id_error_status(self, cr, uid, ids, field_name, arg, context):
        res = {}
        for device in self.browse(cr, uid, ids, context=context):
            res[device.id] = 'REMOTE HOST IDENTIFICATION HAS CHANGED' in (device.errors or '')
        return res


    def update_status(self, cr, uid, ids, context=None):
        if isinstance(ids, (int, long)):
            ids = [ids]
        ips = ','.join([d['ip_addr'] for d in self.read(cr, uid, ids, context=context)])
        command = '%s for-openerp %s/32 --scan-timeout 180 -v' % (QUERY_SCRIPT, ips)
        _logger.info('running %r', command)
        result = Execute(command, pty=True)
        if result.returncode or result.stderr:
            _logger.error('ip_network update of %s failed with %r' % (ips, result.stderr.strip() or result.returncode))
            message = ['===================\n', 'return code: %s' % result.returncode]
            if result.stderr.strip():
                message.append('--- stderr ---')
                message.append(result.stderr.strip())
            _logger.error('\n' + '\n'.join(message) + '\n')
        return {'type':'ir.actions.client', 'tag':'reload'}

    def _get_current_screenshots(self, cr, uid, ids, field_name, value, context):
        "return html snippet with links to latest images"
        screenshot = '<div><img src="/ip_network/screenshot/retrieve/?ip=%s&file=%s" width="100%%"></div>'
        res = {}.fromkeys(ids, '')
        perms, paths = self.fnxfs_field_info(cr, uid, ids, 'screenshots', context=context)
        for dev_id, root, trunk, branch, leaf in paths:
            target_path = reduce(div, [p for p in [root, trunk, branch, leaf] if p])
            if target_path.exists():
                files = target_path.glob()
            else:
                files = []
            if not files:
                res[dev_id] = "<h3>No images found.</h3>"
                continue
            device = self.browse(cr, uid, dev_id, context=context)
            files.sort(reverse=True)
            snippets = []
            for f in files:
                if f.isfile() or (f/'CURRENT').isfile():
                    snippets.append(screenshot % (device.ip_addr, f.filename))
                if len(snippets) == 3:
                    break
            res[dev_id] = '\n'.join(snippets)
        return res

    def _get_scripts(self, cr, uid, ids, field_name, arg, context):
        script_ids = self.pool.get('ip_network.device.script')._update_scripts(cr, uid, context=context)
        res = dict(
            (r['id'], script_ids)
            for r in self.read(
                cr, SUPERUSER_ID, [('id','!=',0)], fields=['id'], context={'active_test': False},
                ))
        return res

    def _set_scripts(self, cr, uid, id, name, value, args=None, context=None):
        device_script = self.pool.get('ip_network.device.script')
        for cmd, target_id, update in value:
            if cmd != 1:
                raise ERPError('Logic Error', '%r is not supported for ws_scripts field' % cmd)
            device_script.write(cr, uid, target_id, update, context=context)
        return True

    _columns = {
        'name': fields.char('Name', size=64),
        'ip_addr': fields.char('IP Address', size=15, required=True),
        'ip_addr_as_int': fields.function(
            _ip2int,
            type='char',		# actual integers too big for the backend
            string='IP as int',
            size=10,
            store={
                'ip_network.device': (self_ids, ['ip_addr'], 10),
                },
            ),
        'type_id': fields.many2one('ip_network.device.type', 'Device Type', required=True, ondelete='restrict'),
        'type_source': fields.selection(DeviceTypeSource, 'Device Type source', required=True),
        'status': fields.selection(DeviceStatus, 'Status'),
        'last_comms': fields.datetime('Last Communication'),
        'clues': fields.text('Problem areas'),
        'clues_kanban': fields.text('Problem areas (kanban view)'),
        'errors': fields.html('Errors encountered'),
        # image: all image fields are base64 encoded and PIL-supported
        'image': fields.function(
            _get_image,
            type='binary',
            string="Image",
            multi='image',
            help="This field holds the image used as visual aid to pc status",
            ),
        'image_medium': fields.function(
            _get_image,
            type='binary',
            string="Medium Image",
            multi='image',
            help="This field holds the image used as visual aid to pc status",
            ),
        'image_small': fields.function(
            _get_image,
            type='binary',
            string="Small Image",
            multi='image',
            help="This field holds the image used as visual aid to pc status",
            ),
        'device_files': files('device', string='Miscellaneous Files'),
        'ws_scripts': fields.function(
            _get_scripts,
            fnct_inv=_set_scripts,
            type='one2many',
            relation='ip_network.device.script',
            string='Workstation Scripts',
            help='scripts that will be run on remote workstations',
            ),
        'error_host_id_changed': fields.function(
            _get_host_id_error_status,
            type='boolean',
            string='Host ID changed',
            store=False,
            ),
        'notes': fields.text('Notes'),
        'notes_html': fields.function(
            stonemark2html,
            arg='notes',
            type='html',
            string='Notes (HTML)',
            store={
                'ip_network.device': (self_ids, ['notes'], 10),
                }
            ),
        'pulse_ids': fields.many2many(
            'ip_network.pulse',
            'ipnetwork_dev2pulse_rel', 'device_id', 'pulse_id',
            string='Pulse Issues',
            ),
        'recent_screenshots': fields.function(
                _get_current_screenshots,
                type='html',
                string='Screen Shots',
                ),
        'screenshots': files('screenshot', string='Screenshots', style='images', sort='newest'),
        }

    _defaults = {
            'type_source': DeviceTypeSource.user,
            }

    _sql_constraints = [
            ('ip_addr_unique', 'unique(ip_addr_as_int)', 'That IP address already exists.'),
            ]

    def button_activate(self, cr, uid, ids, context=None):
        # set status to retired
        if isinstance(ids, (int, long)):
            ids = [ids]
        for dev in self.browse(cr, uid, ids, context=context):
            # only process the first ip (should only have been one, anyway)
            return self.update_status(cr, uid, dev.id, context=context)

    def button_ignore(self, cr, uid, ids, context=None):
        # set status to retired
        if isinstance(ids, (int, long)):
            ids = [ids]
        for dev in self.browse(cr, uid, ids, context=context):
            # only process the first ip (should only have been one, anyway)
            dev.status = DeviceStatus.retired

    def button_remove_key(self, cr, uid, ids, context=None):
        if isinstance(ids, (int, long)):
            ids = [ids]
        for dev in self.browse(cr, uid, ids, context=context):
            # only process the first ip (should only have been one, anyway)
            if 'REMOTE HOST IDENTIFICATION HAS CHANGED' not in dev.errors:
                raise ERPError('Logic Error','%s not showing host id changed error, this should not be happening' % dev.ip_addr)
            job = Execute('ssh-keygen -f "/home/openerp/.ssh/known_hosts" -R %s' % dev.ip_addr, pty=True)
            if job.returncode:
                raise ERPError('O/S Error', '\n---\n'.join([job.stdout, job.stderr]))
            job = Execute('ssh %s' % dev.ip_addr, pty=True, input='yes\n', timeout=300)
            return self.update_status(cr, uid, dev.id, context=context)


class screenshot(osv.Model):
    "on-line session screen shot"
    _name = 'ip_network.device.screenshot'
    _rec_name = 'name'
    _order = 'device_addr_as_int asc, name desc'

    def _get_screenshot(self, cr, uid, ids, field_name, value, context):
        res = {}
        ind = self.pool.get('ip_network.device')
        for ss in self.browse(cr, uid, ids, context=context):
            perms, (root, trunk, branch, leaf) = ind.fnxfs_field_info(cr, uid, ss.device_id.id, 'screenshots', context=context)
            target_path = reduce(div, [p for p in [root, trunk, branch, leaf] if p])
            with open(target_path/ss.name, 'rb') as image:
                data = image.read().encode('base64')
            res[ss.id] = data
        return res

    _columns = {
        'name': fields.char('Image Name', size=64, help='timestamp of image'),
        'image': fields.function(
                _get_screenshot,
                string='Screenshot',
                type='binary',
                ),
        'device_id': fields.many2one('ip_network.device', 'IP Device'),
        'device_addr_as_int': fields.related(
            'device_id', 'ip_addr_as_int',
            string='Device address',
            type='char',
            store=True,
            ),
        }


class command(osv.Model):
    "command to probe type and capabilities of a device"
    _name = 'ip_network.extra.command'
    _order = 'sequence asc, name asc'

    _columns = {
        'active': fields.boolean('Active'),
        'name': fields.char('Name', size=32, help='Name of command sequence', required=True),
        'run_for_ids': fields.many2many(
            'ip_network.device.type',
            'ip_network_cmd2dev_rel', 'command_id', 'device_type_id',
            string='Restrict to',
            ),
        'where': fields.selection(TestWhere, 'Test Type', required=True),
        'sequence': fields.integer('Sequence', help='run order of test [0 - 99, default is 50]'),
        'description': fields.text('Description', help='information about this test'),
        'command': fields.text('Command', help='command to run'),
        # 'script_id': fields.many2one('ip_network.script', 'Script'),
        'script': fields.text(
                'Script',
                help=(
                    'python script to process results of command\n'
                    'input: global variable `text` holds all output from command\n'
                    'completion: `result`: dictionary with `value` (required) and `status` (optional) keys'
                    ),
                ),
        'field_ids': fields.one2many(
            'ip_network.extra.field', 'command_id',
            string='Fields',
            ),
        }

    _defaults = {
        'active': True,
        'sequence': lambda *a: 50,
        }

    _sql_constraints = [
        ('ip_network_extra_command_name_unique', 'unique(name)', 'Command already exists'),
        ]

    def create(self, cr, uid, values, context=None):
        script = values.get('script')
        if script:
            try:
                values['script'] = textwrap.dedent(script).strip()
                compile(values['script'], values['name'], 'exec')
            except Exception:
                raise ERPError('Problem with script', traceback.format_exc())
        # create new command
        return super(command, self).create(cr, uid, values, context=context)

    def write(self, cr, uid, ids, values, context=None):
        script = values.get('script')
        if script:
            try:
                values['script'] = textwrap.dedent(script).strip()
                compile(values['script'], '<script>', 'exec')
            except Exception:
                raise ERPError('Problem with script', traceback.format_exc())
        return super(command, self).write(cr, uid, ids, values, context=context)

class field(osv.Model):
    "extra bits to be tracked on a device"
    _name = 'ip_network.extra.field'

    def _generate_form(self, cr, context=None):
        view = self.pool.get('ir.ui.view')
        dynamic_form = view.browse(cr, SUPERUSER_ID, [('name','=','ip_network.device.dynamic.form')], context=context)[0]
        fields = self.browse(cr, SUPERUSER_ID, context=context)
        fields.sort(key=lambda r: r.string)
        short_fields = []
        long_fields = []
        main_fields = []
        notes = []
        for field in fields:
            if field.name in ('ip_addr', 'type_id') or field.type == 'other':
                continue
            elif field.name in ('ip_name', ):
                main_fields.append(field)
            elif field.type in ('html', 'text'):
                long_fields.append(field)
            else:
                short_fields.append(field)
            if field.notes:
                notes.append(field)
        if short_fields or long_fields:
            doc = Xaml(dynamic_devices).document.pages[0]
            arch = doc.string(
                    short_fields=short_fields,
                    long_fields=long_fields,
                    notes_tests=notes,
                    main_fields=main_fields,
                    )
            view.write(cr, SUPERUSER_ID, [dynamic_form.id], {'arch':arch}, context=context)

    def _verify_name(self, name):
        if name[0].isalpha():
            for ch in name:
                if ch not in '_abcdefghijklmnopqrstuvwxyz':
                    break
            else:
                return
        raise ERPError(
                'bad name',
                'name must be all lowercase, may contain "_", but must start with a letter',
                )

    # def _get_compound_type(self, cr, uid, ids, field_name, arg, context):
    #     if not ids:
    #         return {}
    #     if isinstance(ids, (int, long)):
    #         ids = [ids]
    #     for test_field in self.read(cr, uid, ids, context=context):



    _columns = {
        'name': fields.char('Name', size=32, help='database name for field', required=True),
        'string': fields.char('String', size=32, help='Display name for field', required=True),
        'type': fields.selection(
            FieldType,
            'Result Type',
            required=True,
            help='a type of `other` means this is not a field, but code for another field',
            ),
        # 'type_display': fields.function(
        #     _get_compound_type,
        #     type='char',
        #     size=64,
        #     string='Result Type',
        #     selectable=False,
        #     store={
        #         'ip_network.extra.field': (self_ids, ['type', 'size'], 10),
        #         },
        #     ),
        'size': fields.integer('Size'),
        'help': fields.text('Help', help='tooltip to display on form'),
        'notes': fields.boolean('Notes'),
        'command_id': fields.many2one('ip_network.extra.command', string='Command', ondelete='set null'),
        'command_run_for_ids': fields.related(
            'command_id', 'run_for_ids',
            obj='ip_network.device.type',
            rel='ip_network_cmd2dev_rel', id1='command_id', id2='device_type_id',
            string='Restrict to',
            type='many2many',
            ),
        }

    _sql_constraints = [
        ('ip_network_extra_field_name_unique', 'unique(name)', 'Field name already exists'),
        ]

    def create(self, cr, uid, values, context=None):
        if not values.get('string', None):
            values['string'] = values['name'].replace('_', ' ').title()
        if values.get('type') == 'char' and not values.get('size'):
            values['size'] = 32
        # create new field
        new_id = super(field, self).create(cr, uid, values, context=context)
        # update device table
        self.pool.get('ip_network.device')._add_extra_field(
                cr,
                extra_fields=[{
                        'name': values['name'],
                        'string': values['string'],
                        'type': values['type'],
                        'size': values.get('size', False),
                        'help': values.get('help', False),
                        'readonly': True,
                        }])
        # now update the ip_network.device.dynamic.form view to include the new field
        self._generate_form(cr, context=context)
        return new_id

    def unlink(self, cr, uid, ids, context=None):
        if isinstance(ids, (int, long)):
            ids = [ids]
        dev = self.pool.get('ip_network.device')
        names_to_remove = []
        for record in self.browse(cr, uid, ids, context=context):
            names_to_remove.append(record.name)
        for field_name in names_to_remove:
            if (
                uid != SUPERUSER_ID
                and dev.search(cr, uid, [(field_name, '!=', False)], count=True, context=context)
                ):
                raise ERPError(
                        'Field has data',
                        'Unable to remove field %r as some devices have data for that field'
                            % (record.name,)
                            )
        dev._remove_extra_field(cr, names_to_remove)
        result = super(field, self).unlink(cr, uid, ids, context=context)
        self._generate_form(cr, context=context)
        return result

    def write(self, cr, uid, ids, values, context=None):
        if isinstance(ids, (int, long)):
            ids = [ids]
        dev = self.pool.get('ip_network.device')
        for forbidden in ('field_type', ):
            if forbidden in values:
                raise ERPError('Error', 'Field type cannot be changed.')
        extra_fields = []
        if 'name' in values:
            if len(ids) > 1:
                raise ERPError('Error', 'Cannot change multiple records to the same name')
            new_name = fix_field_name(values['name'])
            values['name'] = new_name
            # get previous values
            previous_records = self.read(cr, uid, ids, context=context)
            for record in previous_records:
                extra_fields.append({
                    'name': new_name,
                    'old_name': record['name'],
                    'string': record['string'],
                    })
            # update auxillary models and postgres tables
            dev._add_extra_field(cr, extra_fields, mode='rename')
        # update current model
        result = super(field, self).write(cr, uid, ids, values, context=context)
        try:
            self._generate_form(cr, context=context)
        except ValidateError:
            if extra_fields:
                for f in extra_fields:
                    f['name'], f['old_name'] = f['old_name'], f['name']
                dev._add_extra_field(cr, extra_fields, mode='rename')
            raise
        return result


class remote_scripts(osv.Model):
    "scripts for execution on remote machine"
    #
    _name = 'ip_network.device.script'

    def _update_scripts(self, cr, uid, context=None):
        all_ctx = (context or {}).copy()
        all_ctx['active_test'] = False
        current_scripts = get_scripts()
        current_records = dict(
            (r['filename'], r)
            for r in self.read(cr, uid, [('id','!=',0)], context=all_ctx)
            )
        script_ids = [r['id'] for r in current_records.values()]
        seen = set()
        for filename, info in current_scripts.items():
            seen.add(filename)
            oe_rec = current_records.get(filename)
            if oe_rec is None:
                # create missing record
                info = dict(
                        (k, v)
                        for k, v in info.items()
                        if k not in ('updated', 'm_time')
                        )
                script_ids.append(self.create(cr, SUPERUSER_ID, info, context=all_ctx))
            elif info['updated']:
                changes = {}
                for k, v in info.items():
                    if k in ('updated', 'm_time', ):
                        continue
                    if v != oe_rec[k]:
                        changes[k] = v
                self.write(cr, SUPERUSER_ID, oe_rec['id'], changes, context=all_ctx)
        return script_ids

    _columns = {
        'name': fields.char('Name', size=64, required=True),
        'active': fields.boolean('Active'),
        'filename': fields.char('File name', size=256, readonly=True),
        'shebang': fields.char('Shebang', size=128, readonly=True),
        'arguments': fields.char('Script Arguments', size=128),
        'type': fields.char('Type', size=24, readonly=True),
        'run_by_user': fields.boolean('Run by user'),
        'run_as_user': fields.boolean('Run as user'),
        'script': fields.text('Script', readonly=True),
        # image: all image fields are base64 encoded and PIL-supported
        'image': fields.binary(
                "Image",
                help="This field holds the image used for this script type, limited to 1024x1024px",
                ),
        'image_medium': fields.binary(
                "Medium-sized image",
                help="Medium-sized image of this script. It is automatically "
                     "resized as a 128x128px image, with aspect ratio preserved. "
                     "Use this field in form views or some kanban views.",
                     ),
        'image_small': fields.binary(
                "Small-sized image",
                help="Small-sized image of this script. It is automatically "
                     "resized as a 64x64px image, with aspect ratio preserved. "
                     "Use this field anywhere a small image is required.",
                     ),
        'has_image': fields.boolean("Image"),
        'summary': fields.text('Summary'),
        'summary_html': fields.function(
                stonemark2html,
                arg='summary',
                type='html',
                string='Summary (HTML)',
                store={
                    'ip_network.device.script': (self_ids, ['summary'], 10),
                    }
                ),
        }

    def run_script(self, cr, uid, ids, context=None):
        # copy script to remote machine, run it, display results
        ctx = (context or {}).copy()
        target_ip = ctx.get('target_ip', 'localhost')
        ctx['ip_addr'] = target_ip
        if isinstance(ids, (int, long)):
            [id] = ids
        else:
            id = ids
        script = self.read(cr, uid, id, context=ctx)[0]
        filename = script['filename']
        run_as_user = script['run_as_user']
        try:
            commandline = 'ssh root@%s "mkdir -p /tmp/openerp/bin"' % (target_ip, )
            job = Job(
                    commandline,
                    pty=True,
                    )
            job.communicate(
                    password=CONFIG.network.pw,
                    timeout=60,
                    password_timeout=10,
                    )
            if job.returncode:
                raise Exception('target directory creation failed')
        except Exception as e:
            ctx['exception'] = str(e)
        else:
            try:
                commandline = 'scp -p %s root@%s:/tmp/openerp/bin/' % (WS_SCRIPT_LOCATION / filename, target_ip)
                job = Job(
                        commandline,
                        pty=True,
                        )
                job.communicate(
                        password=CONFIG.network.pw,
                        timeout=60,
                        password_timeout=10,
                        )
                if job.returncode:
                    raise Exception('copy failed')
            except Exception as e:
                ctx['exception'] = str(e)
            else:
                args = (script['arguments'] or '').replace('$IP', target_ip)
                if run_as_user:
                    user = self.pool['res.users'].read(cr, uid, uid, context=ctx)['login']
                    commandline = 'ssh root@%s "sudo -u %s /tmp/openerp/bin/%s %s"' % (target_ip, user, filename, args)
                else:
                    commandline = 'ssh root@%s /tmp/openerp/bin/%s %s' % (target_ip, filename, args)
                try:
                    job = Job(commandline, pty=True)
                    job.communicate(password=CONFIG.network.pw, timeout=60, password_timeout=10)
                    if job.returncode:
                        raise Exception('job failed')
                except Exception as e:
                    ctx['exception'] = str(e)
        view_id = self.pool.get('ir.ui.view').search(cr, uid, [('model','=','ip_network.device.script.rseult')])
        lines = job.stdout.split('\n')
        if 'root' in lines[0] and 'password' in lines[0]:
            lines.pop(0)
        output = '\n'.join(lines)
        ctx['commandline'] = commandline
        ctx['returncode'] = job.returncode
        ctx['stdout'] = output
        ctx['stderr'] = job.stderr
        return {
            'view_type': 'form',
            "view_mode": 'form',
            'res_model': 'ip_network.device.script.result',
            'type': 'ir.actions.act_window',
            'target': 'new',
            'name': filename,
            'view_id': view_id,
            'context': ctx,
            }


    def onload(self, cr, uid, ids, context=None):
        self._update_scripts(cr, uid, context=context)
        res = {}
        res['value'] = value = {}
        for record in self.read(
                cr, uid, ids,
                fields=['name','filename','run_by_user','run_as_user','active','script'],
                context=context,
                ):
            for field in ('name','filename','run_by_user','run_as_user','active','script'):
                value[field] = record[field]
        return res


class pulse(osv.Model):
    "track health of network devices and jobs"
    _name = 'ip_network.pulse'
    _order = 'trigger_device_state desc, state desc, name asc'

    def _calc_name(self, cr, uid, ids, field_name, arg, context):
        """
        The name of a record is the IP address of the device and the description.
        """
        res = {}.fromkeys(ids, False)
        for rec in self.browse(cr, SUPERUSER_ID, ids, context=context):
            res[rec.id] = '%s::%s' % (rec.ip_addr, rec.job)
        return res

    def _get_pulse_ids_from_beat(pulse_beat, cr, uid, beat_ids, context=None):
        pulse_ids = [p['pulse_id'][0] for p in pulse_beat.read(cr, uid, beat_ids, ['pulse_id'], context=context)]
        return pulse_ids

    def _process_timestamps(self, cr, uid, ids, field_names, arg, context):
        """
        calculate `deadline` and `last_seen` fields
        """
        res = {}.fromkeys(ids, {})
        if not (field_names and ids):
            return res
        pulse_beat = self.pool.get('ip_network.pulse.beat')
        for pulse in self.read(cr, uid, ids, ['last_seen','frequency','beat_ids'], context=context):
            pulse_id = pulse['id']
            beats = pulse_beat.read(cr, uid, [('pulse_id','=',pulse_id)], fields=['timestamp','action'], context=context)
            if not beats:
                continue
            else:
                beats.sort(key=lambda b: b['timestamp'], reverse=True)
                beat = beats[0]
                # create new dict or all ids will share the same values because of the `fromkeys()` above
                res[pulse_id] = {}
                res[pulse_id]['last_seen'] = last_seen = beat['timestamp']
                res[pulse_id]['last_seen_id'] = beat['id']
                freq = JF(pulse['frequency'])
                if freq is URGENT:
                    # we don't expect urgent issues
                    continue
                last_date = DateTime.strptime(last_seen, DEFAULT_SERVER_DATETIME_FORMAT)
                if freq is CONTINUOUS:
                    # 30 minute grace period
                    res[pulse_id]['deadline'] = last_date.replace(delta_minute=+30)
                elif freq is INTERMITTENT:
                    # 120 minute grace period between 05:00 - 18:00
                    eod = last_date.replace(hour=18)
                    target_date = last_date.replace(delta_hour=+1)
                    if target_date > eod:
                        target_date = target_date.replace(delta_day=+1, hour=5, minute=30)
                    res[pulse_id]['deadline'] = target_date
                elif freq is DAILY:
                    res[pulse_id]['deadline'] = FederalHoliday.next_business_day(last_date.replace(delta_day=+1, delta_hour=+2))
                elif freq is WEEKLY:
                    res[pulse_id]['deadline'] = FederalHoliday.next_business_day(last_date.replace(delta_day=+7, delta_hour=+2))
                elif freq is MONTHLY:
                    res[pulse_id]['deadline'] = FederalHoliday.next_business_day(last_date.replace(delta_month=+1, delta_hour=+2))
                elif freq is QUARTERLY:
                    res[pulse_id]['deadline'] = FederalHoliday.next_business_day(last_date.replace(delta_month=+3, delta_hour=+2))
                elif freq is YEARLY:
                    res[pulse_id]['deadline'] = FederalHoliday.next_business_day(last_date.replace(delta_year=+1, delta_hour=+2))
                else:
                    # unknown, make it late
                    res[pulse_id]['deadline'] = last_date.replace(delta_day=-1)
        return res

    _columns = {
        'name': fields.function(
            _calc_name,
            string='Device/Job',
            type='char',
            size=288,
            store={
                'ip_network.pulse': (self_ids, ['ip_addr','job'], 10),
                },
            ),
        'state': fields.selection(JobStatus, 'Status', required=True),
        'ip_addr': fields.char('IP Address', size=15, required=True),
        'ip_addr_as_int': fields.function(
            _ip2int,
            type='char',		# actual integers too big for the backend
            string='IP as int',
            size=10,
            store={
                'ip_network.pulse': (self_ids, ['ip_addr'], 10),
                },
            ),
        'job': fields.char('Job name', size=256, required=True),
        'frequency': fields.selection(JobFrequency, 'Job Frequency', required=True),
        'last_seen': fields.function(
            _process_timestamps,
            type='datetime',
            string='Last report',
            multi='timestamp',
            store={
                'ip_network.pulse.beat': (_get_pulse_ids_from_beat, ['timestamp'], 10),
                },
            ),
        'last_seen_id': fields.function(
            _process_timestamps,
            type='many2one',
            string="Last beat",
            relation='ip_network.pulse.beat',
            multi='timestamp',
            store={
                'ip_network.pulse.beat': (_get_pulse_ids_from_beat, ['timestamp'], 10),
                },
            ),
        'deadline': fields.function(
            _process_timestamps,
            fnct_inv=True,
            type='datetime',
            string='Next due',
            multi='timestamp',
            readonly=True,
            states={'sleeping': [('readonly', False)]},
            store={
                'ip_network.pulse.beat': (_get_pulse_ids_from_beat, ['timestamp'], 10),
                },
            ),
        'beat_ids': fields.one2many('ip_network.pulse.beat', 'pulse_id', string='Beats'),
        'device_ids': fields.many2many(
            'ip_network.device',
            'ipnetwork_dev2pulse_rel', 'pulse_id', 'device_id',
            string='Device',
            ),
        'paused_reason': fields.char('Reason for suspension', size=128),
        'trigger_device_state': fields.boolean('Update device status'),
        }

    _defaults = {
        'state': NORMAL,
        'trigger_device_state': False,
        }

    _sql_constraints = [
        ('identifier_uniq', 'unique(ip_addr,job)', 'job already exists'),
        ]

    def onchange_state(self, cr, uid, id, new_state, context=None):
        res = {}
        if new_state not in ('normal', 'sleeping'):
            res['value'] = {'state': 'normal'}
        return res

    def process_message_files(self, cr, uid, arg=None, context=None, ids=None):
        match = Var(re.match)
        errors = []
        file_dir = Path('/home/openerp/sandbox/openerp/var/pulse')
        archive_dir = file_dir/'archive'
        if not archive_dir.exists():
            archive_dir.makedirs()
        #
        # collect all the devices; used both for linking pulses and for checking
        # grace periods
        network_device = self.pool.get('ip_network.device')
        devices = dict(
                (d.ip_addr_as_int, d)
                for d in network_device.browse(cr, uid, [(1,'=',1)], context=context)
                )
        # process any files
        for message_file in file_dir.glob('IP*.txt'):
            try:
                with open(message_file) as f:
                    data = f.read()
                data = literal_eval(data
                        .replace('datetime.datetime','')
                        .replace('datetime.date','')
                        .replace('datetime.time','')
                        )
                job = data['job_name']
                ip = data['ip_address']
                freq = JobFrequency(data['frequency'])
                action = data.get('action')
                timestamp = DateTime(*data['timestamp'])
                # convert timestamp from server's timezone to UTC
                timestamp = timestamp.replace(tzinfo=SERVER_TIMEZONE).astimezone(UTC)
                if not action:
                    if freq is URGENT:
                        action = 'trip'
                    else:
                        action = 'ping'
                beat_model = self.pool.get('ip_network.pulse.beat')
                # retrieve or create pulse
                pulse_jobs = self.browse(cr, uid, [('job','=',job),('ip_addr','=',ip)], context=context)
                if pulse_jobs:
                    pulse_job = pulse_jobs[0]
                    pulse_id = pulse_job.id
                    if freq is not URGENT and pulse_job.frequency != freq:
                        self.write(cr, uid, pulse_id, {'frequency': freq}, context=context)
                else:
                    pulse_id = self.create(
                            cr, uid,
                            {'job': job, 'ip_addr': ip, 'frequency': freq, 'last_seen': timestamp},
                            context=context,
                            )
                    # after creating new pulse, link to appropriate devices
                    # primary device is in `ip`, secondary device is in `job`
                    q1, q2, q3, q4 = map(int, ip.split('.'))
                    primary_as_int = '%010d' % ((q1 << 24) + (q2 << 16) + (q3 << 8) + q4)
                    linked_ids = [(4, devices[primary_as_int].id)]
                    if match(r'(\d{1,3})_(\d{1,3})_(\d{1,3})_(\d{1,3})', job):
                        q1, q2, q3, q4 = map(int, match.groups())
                        secondary_as_int = '%010d' % ((q1 << 24) + (q2 << 16) + (q3 << 8) + q4)
                        secondary = devices.get(secondary_as_int)
                        if secondary is not None:
                            linked_ids.append((4, secondary.id))
                    self.write(cr, uid, pulse_id, {'device_ids': linked_ids}, context=context)
                # create beat
                beat_model.create(cr, uid, {'pulse_id':pulse_id, 'timestamp':timestamp, 'action':action}, context=context)
                try:
                    message_file.copy(archive_dir)
                except Exception:
                    _logger.exception('failure copying file')
                finally:
                    message_file.unlink()
                #
                # TODO send text-message/email for each device in urgent
                #
            except Exception as exc:
                _logger.exception('exception raised')
                errors.append((message_file, exc))
        for err in errors:
            _logger.error("file: %r, exc: %r", *err)
        #
        # now check grace periods
        #
        # - collect all pulses that are late (deadline is earlier than right now)
        # - collect all pulses of type `urgent`
        # - collect devices that match the pulses' IP addresses
        # - craft the device status message
        # - for `ping` pulses:
        #   - if the message is not in the `clues` fields, add it
        #   - if the device status is not currently `fix`, change it to `fix`
        # - for `urgent` pulses:
        #   - get beats and sort by timestamp
        #   - if latest beat action is `alert`, all three below; if `trip`, skip the "send message":
        #     - send message and change device status
        #     - ensure message is in `clues`
        #     - ensure device status is `fix`
        #
        # - collect all devices with a status of `fix` (except the ones we just changed to `fix`)
        # - while "pulse" is in the device's status:
        #   - extract pulse name from status message
        #   - look up pulse
        #   - if action is `clear` or `deadline` is later than right now:
        #     - remove pulse from `clues`
        #     - change device status to `good` if no other clues
        #
        # - a pulse message: "pulse: <job name>"
        #
        now = fields.datetime.now(self, cr)
        # collect all the pulses (which are jobs, the beats are the instances of pulses)
        pulses = {}
        for p in self.browse(cr, uid, [(1,'=',1)], context=context):
            pulses.setdefault(p.ip_addr_as_int, []).append(p)
        #
        # handle pulses / devices
        #
        # - get all devices and store current `clues` field, plus a copy
        # - for each device
        #   - check if any current pulse warnings have been resolved
        #   - check if any pulses are past due
        #   - calculate differences between orginal `clues` and updated `clues`, and update OpenERP
        #
        # cycle through the devices
        for dev_int_ip, dev in devices.items():
            trigger_device = False
            old_clues = [c for c in (dev.clues or '').split('\n') if c]
            new_clues = [c for c in old_clues if not c.startswith('pulse: ')]
            old_clues_kanban = [c for c in (dev.clues_kanban or '').split('\n') if c]
            new_clues_kanban = new_clues[:]
            # any pulses?
            count = 0
            count_kanban = 0
            for pulse in dev.pulse_ids:
                trigger_device |= pulse.trigger_device_state
                if pulse.state == HISTORICAL:
                    # no longer running
                    continue
                if pulse.state == SUSPENDED:
                    # have we passed the suspended date?
                    if now < pulse.deadline:
                        # nope, ignore it
                        continue
                new_state = NORMAL
                beat = pulse.last_seen_id
                message = 'pulse: %s jobs'
                # if beat action is PING, compare next expected date with now to see if it missed
                # checking in
                if beat.action == PING:
                    if now > pulse.deadline:
                        # make sure message is in clues
                        count += 1
                        # make sure status is OVERDUE
                        new_state = OVERDUE
                        if pulse.trigger_device_state:
                            count_kanban += 1
                elif beat.action in (ALERT, TRIP):
                    new_state = FAILED
                    count += 1
                    if pulse.trigger_device_state:
                        count_kanban += 1
                    if beat.action is ALERT:
                        # TODO: notify via text message
                        pass
                else: # beat action must be CLEAR
                    pass
                # make sure status is current
                if pulse.state is not new_state:
                    self.write(cr, uid, pulse.id, {'state':new_state}, context=context)
            # processed all the pulses for this device -- have the clues changed?
            if count:
                new_clues.append(message % count)
            if count_kanban:
                new_clues_kanban.append(message % count_kanban)
            values = {}
            if sorted(old_clues) != sorted(new_clues):
                values['clues'] = '\n'.join(new_clues)
            if sorted(old_clues_kanban) != sorted(new_clues_kanban):
                values['clues_kanban'] = '; '.join(new_clues_kanban)
            if trigger_device and dev.status != DANGER:
                values['status'] = (GOOD, WARNING)[bool(new_clues)]
            if values:
                network_device.write(cr, uid, dev.id, values, context=context)
        return True


    def purge_pulse_beats(self, cr, uid, arg=None, context=None, ids=None):
        # should be run every half-hour
        #
        # remove excess files
        archive_dir = Path('/home/openerp/sandbox/openerp/var/pulse/archive')
        job_files = {}
        count = 0
        for message_file in archive_dir.listdir():
            count += 1
            job, date = message_file[:-20], message_file[-19:-4]
            job_files.setdefault(job, []).append(date)
        for job, files in job_files.items():
            files.sort(reverse=True)
            for date in files[50:]:
                filename = '%s-%s.txt' % (job, date)
                archive_dir.unlink(filename)
        # remove excess beats
        pulse_beat = self.pool.get('ip_network.pulse.beat')
        for pulse in self.browse(cr, uid, [('id','!=',0)], context=context):
            beats = sorted(pulse.beat_ids, key=lambda rec: rec.timestamp)[:-20]
            pulse_beat.unlink(cr, uid, [b.id for b in beats], context=context)


class pulse_beat(osv.Model):
    """
    an instance of a pulse
    """
    _name = 'ip_network.pulse.beat'
    _order = 'name desc'

    def _calc_name(self, cr, uid, ids, field_name, arg, context):
        """
        name is date/time of beat and pulse name and frequency
        """
        res = {}
        for rec in self.browse(cr, SUPERUSER_ID, ids, context=context):
            dt = fields.datetime.server_time(self, cr, rec.timestamp)  # convert from UTC to server's time-zone
            dt = dt.strftime('%Y-%m-%d %H:%M:%S')
            res[rec.id] = '[%s] %s::%s' % (dt, rec.pulse_id.ip_addr, rec.pulse_id.job)
        return res

    def _get_ids_from_pulse(pulse_table, cr, uid, changed_ids, context=None):
        self = pulse_table.pool.get('ip_network.pulse.beat')
        ids = self.search(cr, uid, [('id','in',changed_ids)], context=context)
        return ids

    _columns = {
        'name': fields.function(
            _calc_name,
            string='Name',
            type='char',
            size=324,
            store={
                'ip_network.pulse.beat': (self_ids, ['timestamp'], 10),
                'ip_network.pulse': (_get_ids_from_pulse, ['device','job'], 20),
                },
            ),
        'pulse_id': fields.many2one('ip_network.pulse', 'Pulse', required=True, ondelete='cascade'),
        'timestamp': fields.datetime('Reported', required=True),
        'action': fields.selection(BeatAction, string='Action'),
        }



# utilities

def field_to_dict(command):
    f_type = command.type
    if f_type == 'time':
        f_type = 'float'
    res = {'type':f_type}
    if command.where != 'user':
        res['readonly'] = True
    for arg in ('string', 'help', 'size'):
        value = getattr(command, arg, None)
        if value:
            res[arg] = value
    return res

class Blocks(object):
    "yields one block of text at a time"
    def __init__(self, text, length=None):
        self.lines = text.strip().split('\n')
        self.lines.reverse()
        self.length = length
    def __iter__(self):
        lines = self.lines
        length = self.length
        while 'processing lines':
            block = []
            while lines:
                line = lines.pop()
                if length is None and not line.strip():
                    # if blocks are blank-line delimited
                    break
                block.append(line)
                if len(block) == length:
                    # if blocks are fixed-size
                    break
            if block:
                yield block
            if not lines:
                break

class OEDatom(dict):
    "custom dict to track 'id' outside the dict values"
    id = None

def _validate_bool(value):
    if value in (True, False):
        return value
    return None

def _validate_int(value):
    if isinstance(value, (int, long)):
        return value
    return None

def _validate_float(value):
    if isinstance(value, float):
        return value
    return None

def _validate_date(value):
    try:
        value = value.strftime(DEFAULT_SERVER_DATE_FORMAT)
        return value
    except Exception:
        return None

def _validate_datetime(value):
    try:
        return value.strftime(DEFAULT_SERVER_DATETIME_FORMAT)
    except Exception:
        return None

def _validate_time(value):
    try:
        return Time(value).tofloat()
    except Exception:
        return None

def _validate_text(value):
    if isinstance(value, (str, unicode)):
        return value
    return None
_validate_html = _validate_text
_validate_char = _validate_text

def first(thing):
    return thing[0]

def str_seq(thing):
    return ', '.join(str(i) for i in thing)

_lower = translator(
     frm='ABCDEFGHIJKLMNOPQRSTUVWXYZ ',
      to='abcdefghijklmnopqrstuvwxyz_',
    keep='abcdefghijklmnopqrstuvwxyz_0123456789',
   strip='_',
    )

def fix_field_name(name):
    name = name.replace('<=', '_le_').replace('>=', '_ge_').replace('<', '_lt_').replace('&', '_and_').replace('>', '_gt').replace('=', '_eq_').replace('!=', '_ne_')
    return _lower(name)

def get_scripts():
    match = Var(re.match)
    with NamedLock('ip_network.device.script'):
        seen = set()
        for script in WS_SCRIPT_LOCATION.glob('*'):
            info = WS_SCRIPTS.setdefault(script.filename, {
                    'filename': script.filename,
                    'arguments': None,
                    'shebang': None,
                    'name': None,
                    'run_by_user': None,
                    'run_as_user': None,
                    'script': None,
                    'active': True,
                    'updated': None,
                    'm_time': 0,
                    })
            info['updated'] = False
            seen.add(script.filename)
            if info['m_time'] != script.stat().st_mtime:
                # something may have changed, update entry
                #
                # shebang
                # name in OpenERP
                # runnable by users
                # script (without above meta)
                # m_time
                #
                info['updated'] = True
                info['m_time'] = script.stat().st_mtime
                text = []
                with script.open() as i:
                    data = i.read().split('\n')
                looking = True
                for line in data:
                    if not looking:
                        pass
                    elif line[:1] != '#':
                        # stop processing at first non-comment line
                        looking = False
                        # if this is a zip app, stop storing lines
                        if line[:4] == 'PK\x03\x04':
                            text.append('...zip app file...')
                            break
                    elif line.startswith('#!'):
                        if info['shebang'] is not None:
                            _logger.warning('%r has multiple shebang lines', script)
                        else:
                            info['shebang'] = line
                    elif match('#\s?OERP.?NAME:\s*(.*)$', line, re.I):
                        if info['name'] is not None:
                            _logger.warning("%r has multiple `#OERP NAME` entries", script)
                        else:
                            [info['name']] = match().groups()
                        continue
                    elif match('#\s?OERP.?RUN.?BY.?USER.?:\s*(.*)$', line, re.I):
                        if info['run_by_user'] is not None:
                            _logger.warning("%r has multiple `#OERP RUN BY USER` entries", script)
                        else:
                            [info['run_as_user']] = match().groups()
                        continue
                    elif match('#\s?OERP.?RUN.?AS.?USER.?:\s*(.*)$', line, re.I):
                        if info['run_as_user'] is not None:
                            _logger.warning("%r has multiple `#OERP RUN AS USER` entries", script)
                        else:
                            info['user_runnable'] = match().groups()[0].lower() in ('y', 'yes', 't', 'true')
                        continue
                    elif match('#\s?OERP.?ACTIVE:\s*(.*)$', line, re.I):
                        if info['run_as_user'] is not None:
                            _logger.warning("%r has multiple `#OERP ACTIVE` entries", script)
                        else:
                            info['user_runnable'] = match().groups()[0].lower() in ('y', 'yes', 't', 'true')
                        continue
                    elif match('#\s?OERP.?CMD.?ARGS:\s*(.*)$', line, re.I):
                        if info['arguments'] is not None:
                            _logger.warning("%r has multiple `#OERP CMD ARGS` entries", script)
                        else:
                            [info['arguments']] = match().groups()
                        continue
                    # pass all other lines through
                    text.append(line)
                if info['shebang'] is not None:
                    info['script'] = '\n'.join(text)
                else:
                    info['shebang'] = False
                    info['script'] = False
                if info['name'] is None:
                    info['name'] = script.base
                for setting in ('run_by_user', 'run_as_user'):
                    if info[setting] is None:
                        info[setting] = False
                info.update(_get_type_and_image(info['shebang']))
                # script processed
            for name in WS_SCRIPTS:
                if name not in seen:
                    WS_SCRIPTS[name]['updated'] = True
                    WS_SCRIPTS[name]['active'] = False
        # return copy of global dict
        return WS_SCRIPTS.copy()

def _get_type_and_image(shebang):
    # return dictionary with `type`, `image`, `image_medium`, `image_small`, and `has_image` keys
    value = {}
    if not shebang:
        # treat as binary
        value.update(getattr(images, 'binary_icon'))
        value['script'] = '...binary file...'
    else:
        for match, type, img in (
                ('python', 'Python', 'python_icon'),
                ('bash', 'Bash', 'bash_icon'),
                ('php', 'PHP', 'php_icon'),
                ('perl', 'Perl', 'perl_icon'),
                ('ruby', 'Ruby', 'ruby_icon'),
                ('sh', 'Shell', 'sh_icon'),
                ):
            if match in shebang:
                value.update(getattr(images, img))
                break
        else:
            # unknown script
            value.update(getattr(images, 'unknown_icon'))
    return value


DEVICE_STATUS = {
    'great':    'green',
    'good':     'green',
    'online':   'yellow',
    'warning':  'yellow',
    'danger':   'red',
    'unknown':  'red',
    'offline':  'black',
    }

TYPES = {
    'html': _validate_html,
    'text': _validate_text,
    'char': _validate_char,
    'boolean': _validate_bool,
    'integer': _validate_int,
    'float': _validate_float,
    'date': _validate_date,
    'datetime': _validate_datetime,
    'time': _validate_time,
    }

dynamic_devices = (
"""\
!!! xml1.0
~data

    -if args.main_fields:
        @name position='after'
            -for field in args.main_fields:
                ~field name=field.name

    -if args.short_fields:
        ~group @short_fields position='inside'
            ~group
                -for field in args.short_fields:
                    -if field.command_run_for_ids:
                        -visible_types = "{'invisible':[('type_id','not in',[" + ','.join([str(i.id) for i in field.command_run_for_ids]) + "])]}"
                        ~field name=field.name attrs=visible_types
                    -else:
                        ~field name=field.name

    -if args.long_fields:
        ~page @misc_files position='before'
            -for field in args.long_fields:
                -if field.command_run_for_ids:
                    -visible_types = "{'invisible':[('type_id','not in',[" + ','.join([str(i.id) for i in field.command_run_for_ids]) + "])]}"
                    ~page string=field.string attrs=visible_types
                        ~pre
                            ~field name=field.name nolabel='1' options="{'no_embed': True}"
                -else:
                    ~page string=field.string
                        ~pre
                            ~field name=field.name nolabel='1' options="{'no_embed': True}"
"""
)

