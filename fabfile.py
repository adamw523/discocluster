import ConfigParser
import Crypto.PublicKey
import dodo
import fabtools
import re

from fabric.utils import abort
from fabric.api import *
from fabric.colors import green as _green
from fabric.colors import yellow as _yellow
from fabric.colors import red as _red
from fabric.contrib.files import *
from fabtools import require

do_master_droplet = 'discomaster'
do_slave_prefix = 'discoslave-'
do_size_id = '66'
do_image_id = '473123'
do_region_id = '1'
do_ssh_key_ids = '16645,4649'

cluster_size = 2

#----------------------------------------
# hosts selection
#----------------------------------------
def _hosts():
    hosts = {}
    with open('private/hosts') as h:
        l = h.readline()
        while l:
            (name, ip) = l.strip().split('\t')
            hosts[name] = ip
            l = h.readline()

    return hosts


def master_ip():
    """
    Get IP address of the master node
    """
    hosts = _hosts()
    if do_master_droplet in hosts:
        print 'master ip address:', hosts[do_master_droplet]
        return hosts[do_master_droplet]

def _slaves_ips():
    hosts = _hosts()
    return [hosts[name] for name in hosts.keys() if _is_slave_name(name)]

def _shared():
    env.user = 'disco'
    env.key_filename = 'private/disco_rsa'
    env.disco_home = '/home/disco/disco'

def master():
    """
    Select master for receiving commands
    """
    _shared()
    env.hosts.append(master_ip())

def slaves():
    """
    Select all slave nodes for receiving commands
    """
    _shared()
    env.hosts.extend(_slaves_ips())

def all_nodes():
    """
    Select all nodes including master and slaves for receiving commands
    """
    _shared()
    env.hosts = [master_ip()] + _slaves_ips()

#----------------------------------------
# disco
#----------------------------------------
def disco_install_requirements():
    """
    Install requirements for runnign disco
    """
    deb_packages = ['erlang', 'lighttpd', 'git', 'build-essential', 'telnet']
    fabtools.require.deb.packages(deb_packages)

def disco_install():
    """
    Install disco
    """
    # bring system up to date
    update_system()

    # add environment variable
    append('/home/disco/.bashrc', 'DISCO_HOME=%s' % env.disco_home)
    run('. /home/disco/.bashrc')

    # install requirements
    disco_install_requirements()

    # get disco
    run('git clone git://github.com/discoproject/disco.git %s' % env.disco_home)
    with cd(env.disco_home):
        run('make')

def disco_start():
    """Start the disco service"""
    with cd(env.disco_home):
        run('./bin/disco start')

def disco_stop():
    """Stop the disco service"""
    with cd(env.disco_home):
        run('./bin/disco stop')

def disco_get_erlang_cookie():
    get('~/.erlang.cookie', 'private/.erlang.cookie')

def disco_put_erlang_cookie():
    run('chmod u+w ~/.erlang.cookie')
    put('private/.erlang.cookie', '~/.erlang.cookie', mode=0600)

#----------------------------------------
# System Level
#----------------------------------------
def firewall():
    """
    Set up firewall rules
    """
    fabtools.require.deb.packages(['ufw']) 
    sudo('ufw default deny')
    sudo('ufw enable')
    sudo('ufw allow ssh')
    #https://github.com/discoproject/disco/blob/master/doc/start/troubleshoot.rst#is-your-firewall-configured-correctly

def update_hosts_file():
    """
    Update /etc/hosts file on nodes
    """
    update_hosts()
    hosts = _hosts()

    lines = ["%s\t%s" % (hosts[host], host) for host in hosts]
    append('/etc/hosts', lines, use_sudo=True)

def update_system(force=False):
    """
    Update apt-get sources, only if force=True OR last update was over a week ago
    """
    print(_green("Updating apt if needed"))

    mfile = run('find /tmp/ -name fab_apt_update -mtime -7  -print')
    if force or len(mfile) is 0:
        sudo('apt-get update')
        sudo('touch /tmp/fab_apt_update')

#----------------------------------------
# root stuff
#----------------------------------------
def root():
    """
    run commands as root, useful before creation of disco user
    """
    env.user = 'root'

def create_disco_user():
    """
    Create the disco user on nodes
    """
    # create ourselves an SSH key if we haven't yet
    if not os.path.exists('private/disco_rsa'):
        create_ssh_key()

    # create the disco user, give sudo group, authenticate with our created SSH key
    if not fabtools.user.exists('disco'):
        fabtools.user.create('disco', ssh_public_keys='private/disco_rsa.pub', group='sudo', shell='/bin/bash')
        fabtools.require.sudoer('disco')

#----------------------------------------
# Utils
#----------------------------------------

def _do_droplet_id(name):
    conn = dodo.connect()
    droplets = conn.droplets()
    for droplet in droplets:
        if droplet['name'] == name:
            return droplet['id']

    return None

def start_cluster():
    """
    Start all nodes of the cluster
    """
    conn = dodo.connect()

    # create master
    droplet_options = {
        'name': do_master_droplet,
        'size_id': do_size_id,
        'image_id': do_image_id,
        'region_id': do_region_id,
        'ssh_key_ids': do_ssh_key_ids
    }
    conn.new_droplet(**droplet_options)

    # create nodes
    for i in range(cluster_size):
        droplet_options = {
            'name': do_slave_prefix + str(i + 1),
            'size_id': do_size_id,
            'image_id': do_image_id,
            'region_id': do_region_id,
            'ssh_key_ids': do_ssh_key_ids
        }
        conn = dodo.connect()
        conn.new_droplet(**droplet_options)

    update_hosts()

def destroy_cluster():
    """
    Destroy all nodes
    """
    with open('private/hosts') as h:
        l = h.readline()
        while l:
            (name, ip) = l.strip().split('\t')

            if name == do_master_droplet or _is_slave_name(name):
                droplet_id = _do_droplet_id(name)
                print 'destroying droplet:', name, droplet_id
                conn = dodo.connect()
                conn.destroy_droplet(droplet_id=droplet_id)

            l = h.readline()

    update_hosts()


def update_hosts():
    """
    Update local /private/hosts file with hosts and ip addresses of nodes
    """
    conn = dodo.connect()
    droplets = conn.droplets()

    # empty out the current hosts file
    with open('private/hosts', 'w') as h:
        pass

    for droplet in droplets:
        # is it master or a slave node?
        if droplet['name']== do_master_droplet or _is_slave_name(droplet['name']):
            with open('private/hosts', 'a') as h:
                h.write('\t'.join([droplet['name'], droplet['ip_address']]) + '\n')

#----------------------------------------
# Utils
#----------------------------------------
def create_ssh_key():
    """
    Crate SSH key locally for use on nodes
    """
    key_size = 1024
    pool = Crypto.PublicKey.RandomPool(key_size)
    pool.stir()
    rsakey = Crypto.PublicKey.RSA.generate(key_size, pool.get_bytes)

    with open('private/disco_rsa', 'w') as k:
        k.write(rsakey.exportKey('PEM'))
    with open('private/disco_rsa.pub', 'w') as k:
        k.write(rsakey.publickey().exportKey('OpenSSH'))

    local('chmod 600 private/disco_rsa*')

def _is_slave_name(name):
    return name.startswith(do_slave_prefix) and \
                re.match(r'^\d+$', name[len(do_slave_prefix):])
