from logging import getLogger
from typing import Dict, Optional, List

from octodns.record import Record
from octodns.source.base import BaseSource


class M365Source(BaseSource):
    SUPPORTS = ('TXT', 'CNAME', 'SRV', 'MX')
    SUPPORTS_GEO = False

    def __init__(self, id, zones: dict = {}, ttl=3600):
        klass = self.__class__.__name__
        self.log = getLogger(f'{klass}[{id}]')
        self.log.debug('__init__: id=%s, name=%s, ttl=%d', id, ttl)
        self.zones = zones
        super().__init__(id)
        self.ttl = ttl

    def populate(self, zone, target=False, lenient=False):
        # This is the method adding records to the zone. For a source it's the
        # only thing that needs to be implemented. Again there's some best
        # practices wrapping our custom logic, mostly for logging/debug
        # purposes.
        self.log.debug(
            'populate: name=%s, target=%s, lenient=%s',
            zone.name,
            target,
            lenient,
        )

        before = len(zone.records)

        if zone.name not in self.zones:
            raise ValueError("zone configuration not found for zone %s" % zone.name)

        zoneconfig: Dict = self.zones[zone.name]

        spf_mode = zoneconfig.get('spf', 'default')
        if spf_mode == 'default':
            spf_data = {
                'type': 'TXT',
                'ttl': self.ttl,
                'values': [
                    "v=spf1 include:spf.protection.outlook.com -all"
                ]
            }
            zone.add_record(
                Record.new(
                    zone,
                    '',
                    spf_data
                )
                , lenient=lenient)
            zone.add_record(
                Record.new(
                    zone,
                    '*',
                    spf_data
                )
                , lenient=lenient)

        autodiscover: Optional[str] = None

        if 'mx' in zoneconfig:
            zone.add_record(
                Record.new(
                    zone,
                    '',
                    {
                        'type': 'MX',
                        'ttl': self.ttl,
                        'values': {
                            'preference': 0,
                            'exchange': zoneconfig["mx"]
                        }
                    }
                )
            )
            mx_wc:bool =  zoneconfig.get("mx_wc", False)
            if type(mx_wc) != bool:
                raise ValueError("mx_wc must be boolean. zone: %s" % zone.name)
            if mx_wc:
                zone.add_record(
                    Record.new(
                        zone,
                        '*',
                        {
                            'type': 'MX',
                            'ttl': self.ttl,
                            'values': {
                                'preference': 0,
                                'exchange': zoneconfig["mx"]
                            }
                        }
                    )
                )
            autodiscover = 'autodiscover.outlook.com.'

        autodiscover = zoneconfig.get('autodiscover') or autodiscover
        if autodiscover:
            zone.add_record(
                Record.new(
                    zone,
                    'autodiscover',
                    {
                        'type': 'CNAME',
                        'ttl': self.ttl,
                        'value': autodiscover
                    }
                )
            )

        intune = zoneconfig.get('intune', True)
        if type(intune) != bool:
            raise ValueError("intune must be boolean. zone: %s" % zone.name)

        if intune:
            zone.add_record(
                Record.new(
                    zone,
                    'enterpriseenrollment',
                    {
                        'type': 'CNAME',
                        'ttl': self.ttl,
                        'value': 'enterpriseenrollment-s.manage.microsoft.com.'
                    }
                )
            )
            zone.add_record(
                Record.new(
                    zone,
                    'enterpriseregistration',
                    {
                        'type': 'CNAME',
                        'ttl': self.ttl,
                        'value': 'enterpriseregistration.windows.net.'
                    }
                )
            )

        dkim: List[str] = zoneconfig.get('dkim', [])
        if type(dkim) is not list:
            raise ValueError("dkim configuration must be a list. zone: %s" % zone.name)
        if len(dkim) != 2:
            raise ValueError("dkim configuration must contain 2 items. zone: %s" % zone.name)
        for i, d in enumerate(dkim):
            zone.add_record(
                Record.new(
                    zone,
                    'selector'+str(i+1)+'._domainkey',
                    {
                        'type': 'CNAME',
                        'ttl': self.ttl,
                        'value': d
                    }
                )
            )

        s4b: bool = zoneconfig.get("s4b", False)
        if type(s4b) != bool:
            raise ValueError("s4b must be boolean. zone: %s" % zone.name)
        if s4b:
            zone.add_record(
                Record.new(
                    zone,
                    'lyncdiscover',
                    {
                        'type': 'CNAME',
                        'ttl': self.ttl,
                        'value': 'webdir.online.lync.com.'
                    }
                )
            )
            zone.add_record(
                Record.new(
                    zone,
                    'sip',
                    {
                        'type': 'CNAME',
                        'ttl': self.ttl,
                        'value': 'sipdir.online.lync.com.'
                    }
                )
            )
            zone.add_record(
                Record.new(
                    zone,
                    '_sip._tls',
                    {
                        'type': 'SRV',
                        'ttl': self.ttl,
                        'values': {
                            'port': 443,
                            'priority': 100,
                            'target': 'sipdir.online.lync.com.',
                            'weight': 1
                        }
                    }
                )
            )
            zone.add_record(
                Record.new(
                    zone,
                    '_sipfederationtls._tcp',
                    {
                        'type': 'SRV',
                        'ttl': self.ttl,
                        'values': {
                            'port': 5061,
                            'priority': 100,
                            'target': 'sipfed.online.lync.com.',
                            'weight': 1
                        }
                    }
                )
            )

        self.log.info(
            'populate:   found %s records, exists=False',
            len(zone.records) - before,
        )
