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
            'base',
            'fnx',
            'mail',
            'wiki',
            ],
    'css': [
            ],
    'update_xml': [
            'security/ip_network_security.xaml',
            'ip_network_view.xaml',
            'ip_network_data.xaml',
            'wiki_view.xaml',
            'security/ir.model.access.csv',
            'wizard/script_result_view.xaml',
            ],
    'test': [],
    'installable': True,
    'active': False,
}
