import json

class vlans_set(object):
	"""docstring for vlans"""
	def __init__(self):
		super(vlans_set, self).__init__()
		self.vlans = {
					  'hosts':{
					  			'00:00:00:00:00:01':{"IP":'10.0.0.1',"VLAN_ID":20},
					  			'00:00:00:00:00:02':{"IP":'10.0.0.2',"VLAN_ID":20},
					  			'00:00:00:00:00:03':{"IP":'10.0.0.3',"VLAN_ID":30},
					  			'00:00:00:00:00:04':{"IP":'10.0.0.4',"VLAN_ID":30},
					  			'00:00:00:00:00:05':{"IP":'10.0.0.5',"VLAN_ID":30}
					  			}
					 }