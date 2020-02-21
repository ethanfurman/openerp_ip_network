from osv import osv, fields

class script_result(osv.TransientModel):
    _name = 'ip_network.device.script.result'
    _description = 'remote script result'

    _columns = {
        'ip_addr': fields.char('IP address', size=48, readonly=True),
        'commandline': fields.char('Command', size=128, readonly=True),
        'returncode': fields.integer('Return Code', readonly=True),
        'stdout': fields.text('Standard Output', readonly=True),
        'stderr': fields.text('Error Output', readonly=True),
        'exception': fields.text('Exception', readonly=True),
        }

    def default_get(self, cr, uid, fields=None, context=None):
        res = {}
        for f in fields:
            res[f] = context.get(f, False)
        return res
