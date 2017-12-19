#

## grep

```
find /Users/ori/repos/github.com/openshift/openshift-ansible -type f -exec grep  -nH -e docker_blocked_registries {} +
roles/openshift_docker_facts/tasks/main.yml:10:      blocked_registries: "{{ openshift_docker_blocked_registries | default(None) }}"
roles/openshift_docker_facts/tasks/main.yml:27:    docker_blocked_registries: "{{ openshift.docker.blocked_registries
roles/docker/tasks/package_docker.yml:67:    reg_fact_val: "{{ docker_blocked_registries| default(None, true) }}"
roles/docker/tasks/systemcontainer_docker.yml:155:    l_docker_blocked_registries: "{{ docker_blocked_registries | default([]) | to_json }}"
roles/docker/templates/daemon.json:19:    "block-registry": {{ l_docker_blocked_registries }}
playbooks/common/openshift-cluster/initialize_oo_option_facts.yml:14:      openshift_docker_blocked_registries: "{{ lookup('oo_option', 'docker_blocked_registries') }}"
playbooks/common/openshift-cluster/initialize_oo_option_facts.yml:15:    when: openshift_docker_blocked_registries is not defined
playbooks/common/openshift-master/scaleup.yml:58:    docker_blocked_registries: "{{ lookup('oo_option', 'docker_blocked_registries') | oo_split }}"
playbooks/common/openshift-node/scaleup.yml:25:    docker_blocked_registries: "{{ lookup('oo_option', 'docker_blocked_registries') | oo_split }}"
inventory/byo/hosts.origin.example:93:#openshift_docker_blocked_registries=registry.hacker.com
inventory/byo/hosts.ose.example:93:#openshift_docker_blocked_registries=registry.hacker.com
```

## roles/openshift_docker_facts/tasks/main.yml

```yaml
- name: Set docker facts
  openshift_facts:
    role: "{{ item.role }}"
    local_facts: "{{ item.local_facts }}"
  with_items:
  - role: docker
    local_facts:
      additional_registries: "{{ openshift_docker_additional_registries | default(None) }}"
      blocked_registries: "{{ openshift_docker_blocked_registries | default(None) }}"
      insecure_registries: "{{ openshift_docker_insecure_registries | default(None) }}"
      selinux_enabled: "{{ openshift_docker_selinux_enabled | default(None) }}"
      log_driver: "{{ openshift_docker_log_driver | default(None) }}"
      log_options: "{{ openshift_docker_log_options | default(None) }}"
      options: "{{ openshift_docker_options | default(None) }}"
      disable_push_dockerhub: "{{ openshift_disable_push_dockerhub | default(None) }}"
      hosted_registry_insecure: "{{ openshift_docker_hosted_registry_insecure | default(openshift.docker.hosted_registry_insecure | default(False)) }}"
      hosted_registry_network: "{{ openshift_docker_hosted_registry_network | default(None) }}"
      use_system_container: "{{ openshift_docker_use_system_container | default(False) }}"
  - role: node
    local_facts:
      sdn_mtu: "{{ openshift_node_sdn_mtu | default(None) }}"

```

## roles/docker/tasks/package_docker.yml

```yaml
- name: Set registry params
  lineinfile:
    dest: /etc/sysconfig/docker
    regexp: '^{{ item.reg_conf_var }}=.*$'
    line: "{{ item.reg_conf_var }}='{{ item.reg_fact_val | oo_prepend_strings_in_list(item.reg_flag ~ ' ') | join(' ') }}'"
  when: item.reg_fact_val != '' and docker_check.stat.isreg is defined and docker_check.stat.isreg
  with_items:
  - reg_conf_var: ADD_REGISTRY
    reg_fact_val: "{{ docker_additional_registries | default(None, true)}}"
    reg_flag: --add-registry
  - reg_conf_var: BLOCK_REGISTRY
    reg_fact_val: "{{ docker_blocked_registries| default(None, true) }}"
    reg_flag: --block-registry
  - reg_conf_var: INSECURE_REGISTRY
    reg_fact_val: "{{ docker_insecure_registries| default(None, true) }}"
    reg_flag: --insecure-registry
  notify:
  - restart docker

```

## roles/docker/tasks/systemcontainer_docker.yml

```yaml
# Set local versions of facts that must be in json format for container-daemon.json
# NOTE: When jinja2.9+ is used the container-daemon.json file can move to using tojson
- set_fact:
    l_docker_insecure_registries: "{{ docker_insecure_registries | default([]) | to_json }}"
    l_docker_log_options: "{{ docker_log_options | default({}) | to_json }}"
    l_docker_additional_registries: "{{ docker_additional_registries | default([]) | to_json }}"
    l_docker_blocked_registries: "{{ docker_blocked_registries | default([]) | to_json }}"
    l_docker_selinux_enabled: "{{ docker_selinux_enabled | default(true) | to_json }}"

```

## docker/templates/daemon.json

```json
{
    "authorization-plugins": ["rhel-push-plugin"],
    "default-runtime": "oci",
    "containerd": "/run/containerd.sock",
    "disable-legacy-registry": false,
    "exec-opts": ["native.cgroupdriver=systemd"],
    "insecure-registries": {{ l_docker_insecure_registries }},
{% if docker_log_driver is defined  %}
    "log-driver": "{{ docker_log_driver }}",
{%- endif %}
    "log-opts": {{ l_docker_log_options }},
    "runtimes": {
	"oci": {
	    "path": "/usr/libexec/docker/docker-runc-current"
	}
    },
    "selinux-enabled": {{ l_docker_selinux_enabled | lower }},
    "add-registry": {{ l_docker_additional_registries }},
    "block-registry": {{ l_docker_blocked_registries }}
}
```

## playbooks/common/openshift-cluster/initialize_oo_option_facts.yml

```yaml
---
- name: Set oo_option facts
  hosts: oo_all_hosts
  tags:
  - always
  tasks:
  - set_fact:
      openshift_docker_additional_registries: "{{ lookup('oo_option', 'docker_additional_registries') }}"
    when: openshift_docker_additional_registries is not defined
  - set_fact:
      openshift_docker_insecure_registries: "{{ lookup('oo_option',  'docker_insecure_registries') }}"
    when: openshift_docker_insecure_registries is not defined
  - set_fact:
      openshift_docker_blocked_registries: "{{ lookup('oo_option', 'docker_blocked_registries') }}"
    when: openshift_docker_blocked_registries is not defined
  - set_fact:
      openshift_docker_options: "{{ lookup('oo_option', 'docker_options') }}"
    when: openshift_docker_options is not defined
  - set_fact:
      openshift_docker_log_driver: "{{ lookup('oo_option', 'docker_log_driver') }}"
    when: openshift_docker_log_driver is not defined
  - set_fact:
      openshift_docker_log_options: "{{ lookup('oo_option', 'docker_log_options') }}"
    when: openshift_docker_log_options is not defined
  - set_fact:
      openshift_docker_selinux_enabled: "{{ lookup('oo_option', 'docker_selinux_enabled') }}"
    when: openshift_docker_selinux_enabled is not defined

```

### oo_option lookup plugin

- lookup_plugins/oo_option.py

```
oo_option lookup plugin for openshift-ansible

Usage:

    - debug:
      msg: "{{ lookup('oo_option', '<key>') | default('<default_value>', True) }}"

This returns, by order of priority:

* if it exists, the `cli_<key>` ansible variable. This variable is set by `bin/cluster --option <key>=<value> …`
* if it exists, the envirnoment variable named `<key>`
* if none of the above conditions are met, empty string is returned
```


```python
# Reason: disable too-few-public-methods because the `run` method is the only
#     one required by the Ansible API
# Status: permanently disabled
# pylint: disable=too-few-public-methods
class LookupModule(LookupBase):
    ''' oo_option lookup plugin main class '''

    # Reason: disable unused-argument because Ansible is calling us with many
    #     parameters we are not interested in.
    #     The lookup plugins of Ansible have this kwargs “catch-all” parameter
    #     which is not used
    # Status: permanently disabled unless Ansible API evolves
    # pylint: disable=unused-argument
    def __init__(self, basedir=None, **kwargs):
        ''' Constructor '''
        self.basedir = basedir

    # Reason: disable unused-argument because Ansible is calling us with many
    #     parameters we are not interested in.
    #     The lookup plugins of Ansible have this kwargs “catch-all” parameter
    #     which is not used
    # Status: permanently disabled unless Ansible API evolves
    # pylint: disable=unused-argument
    def run(self, terms, variables, **kwargs):
        ''' Main execution path '''

        ret = []

        for term in terms:
            option_name = term.split()[0]
            cli_key = 'cli_' + option_name
            if 'vars' in variables and cli_key in variables['vars']:
                ret.append(variables['vars'][cli_key])
            elif option_name in os.environ:
                ret.append(os.environ[option_name])
            else:
                ret.append('')

        return ret
```

## inventory/byo/hosts.ose.example

```
# Docker Configuration
# Add additional, insecure, and blocked registries to global docker configuration
# For enterprise deployment types we ensure that registry.access.redhat.com is
# included if you do not include it
#openshift_docker_additional_registries=registry.example.com
#openshift_docker_insecure_registries=registry.example.com
#openshift_docker_blocked_registries=registry.hacker.com
```
