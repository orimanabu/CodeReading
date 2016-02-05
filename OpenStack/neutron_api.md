# Neutronのコントローラ周り
## 見るところ
- class Router(object) @neutron/wsgi.py
- class APIRouter(wsgi.Router) @neutron/api/v2/router.py

## URLマッピング
- APIRouter.\_\_init\_\_() @neutron/api/v2/router.py

# Security GroupのAPIマッピング
- Securitygroup.get_resources() @neutron/extensions/securitygroup.py

## ML2
### NeutronManager
- NeutronManager.\_\_init\_\_() @neutron/manager.py
- NeutronManager._load_service_plugins() @neutron/manager.py
- NeutronManager._load_services_from_core_plugin() @neutron/manager.py

### ML2Plugin
- ML2Plugin.supported_extension_aliases() @neutron/plugins/ml2/plugin.py

### Security Group extension
- disable_security_group_extension_by_config() @neutron/agent/securitygroup_rpc.py
- is_firewall_enabled() @neutron/agent/securitygroup_rpc.py @neutron/agent/securitygroup_rpc.py
  return cfg.CONF.SECURITYGROUP.enable_security_group

