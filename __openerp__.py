{
   'name': 'IP Network map',
    'version': '0.3',
    'category': 'Generic Modules',
    'description': """\
            Tracks IP devices on the network, allowing the specification and
            customization of fields and data to track.
            """,
    'author': 'Ethan Furman',
    'maintainer': 'Ethan Furman',
    'website': '',
    'depends': [
            'fnx',
            'mail',
            ],
    'css': [
            ],
    'update_xml': [
            'security/ip_network_security.xaml',
            'ip_network_view.xaml',
            'ip_network_data.xaml',
            'security/ir.model.access.csv',
            ],
    'test': [],
    'installable': True,
    'active': False,
}
