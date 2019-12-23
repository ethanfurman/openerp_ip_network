# imports
from antipathy import Path
from dbf import Time
from VSS.utils import translator
from fnx.oe import Normalize
from openerp import CONFIG_DIR, SUPERUSER_ID
from openerp.osv.orm import except_orm as ValidateError
from openerp.exceptions import ERPError
from openerp.tools import DEFAULT_SERVER_DATE_FORMAT, DEFAULT_SERVER_DATETIME_FORMAT, self_ids
from osv import orm, osv, fields
from psycopg2 import ProgrammingError
from scription import Execute, OrmFile
from xaml import Xaml
import images
import logging
import openerp
import os
import pwd
import textwrap
import threading
import traceback

# config
_logger = logging.getLogger(__name__)
config_file = Path('/%s/fnx.ini' % CONFIG_DIR)
known_hosts = Path(pwd.getpwnam('openerp')[5]) / '.ssh/known_hosts'
query_script = Path('/opt/bin/ip_network_query')
virtual_env = os.environ.get('VIRTUAL_ENV')

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
    _order_ = 'online great good warning danger offline unknown'
    online = 'On-line'
    great = 'Great'
    good = 'Good'
    warning = 'Warning'
    danger = 'Fix!'
    offline = 'Off-line'
    unknown = 'Unknown (tar-pit?)'

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
        'short_name': fields.char('Short Name', size=24),
        'description': fields.text(),
        'test': fields.char('Test', size=128),
        'sequence': fields.integer('Run Order'),
        }

    _constraints = [
        (lambda s, *a: s.check_unique('name', *a), '\nDevice type already exists', ['name']),
        ]


class device(osv.Model):
    "a physical device with an IP address"
    _name = 'ip_network.device'
    _rec_name = 'ip_addr'
    _order = 'ip_addr_as_int asc'

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
                # self._all_columns[field_name].string = name
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

    def _ip2int(self, cr, uid, ids, field_name, arg, context):
        res = {}
        for device_rec in self.read(cr, uid, ids, fields=['id','ip_addr'], context=context):
            ip_addr = device_rec['ip_addr']
            quads = ip_addr.split('.')
            if len(quads) != 4:
                 raise ERPError('bad ip address', 'ip address should be a dotted quad [got %r]' % (ip_addr, ))
            try:
                quads = [int(q) for q in quads]
                if not all([0 <= q <= 255 for q in quads]):
                    raise ValueError
            except ValueError:
                raise ERPError('bad ip address', 'quad values should be between 0 - 255 [got %r]' % (ip_addr, ))
            ip_as_int = (quads[0] << 24) + (quads[1] << 16) + (quads[2] << 8) + quads[3]
            res[device_rec['id']] = '%010d' % ip_as_int
        return res

    def update_status(self, cr, uid, ids, context=None):
        config = OrmFile(config_file)
        if isinstance(ids, (int, long)):
            ids = [ids]
        ips = ','.join([d['ip_addr'] for d in self.read(cr, uid, ids, context=context)])
        result = Execute('sudo VIRTUAL_ENV=%s %s for-openerp %s/32 --scan-timeout 180' % (virtual_env, query_script, ips), pty=True, password=config.openerp.pw)
        if result.returncode or result.stderr:
            _logger.error('ip_network update of %s failed with %r' % (ips, result.stderr.strip() or result.returncode))
            message = ['===================\n', 'return code: %s' % result.returncode]
            if result.stderr.strip():
                message.append('--- stderr ---')
                message.append(result.stderr.strip())
            _logger.error('\n' + '\n'.join(message) + '\n')
            raise ERPError('Update Failed', result.stderr.strip())
        return {'type':'ir.actions.client', 'tag':'reload'}

    _columns = {
        'name': fields.char('Name', size=64),
        'ip_addr': fields.char('IP Address', size=15, required=True),
        'ip_addr_as_int': fields.function(
            _ip2int,
            type='char',
            string='IP as int',
            size=10,
            store={
                'ip_network.device': (self_ids, ['ip_addr'], 10),
                },
            ),
        'type_id': fields.many2one('ip_network.device.type', 'Device Type', required=True, ondelete='restrict'),
        'status': fields.selection(DeviceStatus, 'Status'),
        'last_comms': fields.datetime('Last Communication'),
        'clues': fields.text('Problem areas'),
        'errors': fields.text('Errors encountered'),
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
        }

    _sql_constraints = [
            ('ip_addr_unique', 'unique(ip_addr_as_int)', 'That IP address already exists.'),
            ]


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
        ~notebook @notebook_fields position='inside'
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
