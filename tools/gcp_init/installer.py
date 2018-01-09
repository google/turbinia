#!/usr/bin/env python

"""installer automates config GCE and compute instances for turbinia."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import argparse as argp
import imp
import json
import logging as log
import os
import shutil
import sys
import tempfile as tempf
import time
import traceback

import fabric.api as fab
import fabric.contrib.project as fabp
from fabric.exceptions import NetworkError as FabNetworkError

CONFIG_FILE = '../../turbinia/config/turbinia_config.py'
tcfg = imp.load_source('turbiniaconfig', CONFIG_FILE)

try:
  if tcfg.UNCONFIGURED:
    log.fatal('Please customize turbinia\'s configuration file'
              'for your site: {0:s}'.format(CONFIG_FILE))
except AttributeError:
  pass

fab.env.use_ssh_config = True


def Init():
  """Initialize options for this install run.

  Returns:
    opts (argparse namespace class): argparse data structure containing options
  """
  p = argp.ArgumentParser()
  p.add_argument('--verbose', help='enable verbose output',
                 action='store_true', default=False)
  p.add_argument('--debug', help='enable debug messages',
                 action='store_true', default=False)
  p.add_argument('--tmpdir', help='set temporary directory',
                 default=tempf.mkdtemp(dir='/var/tmp', prefix='turbt-'))
  p.add_argument('--cache', help='set cache directory',
                 default=tempf.mkdtemp(dir='/var/tmp', prefix='turbc-'))
  p.add_argument('--no_prune_tc', help='don\'t prune cache and tmp directories',
                 action='store_true', default=False)
  p.add_argument('--troot', help='set local turbinia root directory',
                 default='../../../turbinia')
  p.add_argument('--tdir', help='set remote root directory',
                 default='/usr/local/turbinia')
  p.add_argument('--gce_key_file', help='GCE service account keys file path',
                 default=None)
  opts = p.parse_args()

  if opts.debug:
    log_format = ('%(asctime)s.%(msecs)03d %(lineno)d:%(funcName)s '
                  '%(levelname)s: %(message)s')
  else:
    log_format = '%(asctime)s.%(msecs)03d %(levelname)s: %(message)s'

  log.basicConfig(format=log_format, datefmt='%Y-%m-%d %H:%M:%S')

  logger = log.getLogger()
  if opts.debug:
    logger.setLevel(log.DEBUG)
  else:
    logger.setLevel(log.INFO)

  log.getLogger('paramiko').setLevel(log.WARNING)

  return opts


class GcloudCmd(object):
  """Provides interface to gcloud CLI tool for manipulating gcloud service."""

  def __init__(self, opts=None):
    """Initializes the Google Cloud (gcloud) Command CLI tool wrapper object.

    Returns:
      GcloudCmd object instance
    """
    self.project = tcfg.PROJECT

    self.svc_account_name = tcfg.GCE_SERVICE_ACCOUNT
    self.svc_account = None

    self.required_roles = tcfg.GCE_REQUIRED_ROLES
    self.required_services = tcfg.GCE_REQUIRED_SERVICES

    self.zone = tcfg.ZONE
    self.image_family = tcfg.GCE_IMAGE_FAMILY
    self.image_project = tcfg.GCE_IMAGE_PROJECT
    self.disk_size = tcfg.GCE_BOOT_DISK_SIZE
    self.name_prefix = tcfg.GCE_INSTANCE_NAME_PREFIX

    self.server = tcfg.GCE_SERVER_INSTANCE
    self.worker_prefix = tcfg.GCE_WORKER_INSTANCE
    self.worker_pool_size = tcfg.GCE_WORKER_POOL_SIZE

    if opts and opts.gce_key_file:
      self.svc_account_keys_file = opts.gce_key_file
    else:
      self.svc_account_keys_file = tcfg.GCE_SERVICE_ACCOUNT_KEYS_FILE
    self.gce_ssh_key_file = tcfg.GCE_SSH_KEY_FILE

    self.gcloud_cmd = 'gcloud'
    self.common_options = '--format=json'

    if self.project:
      self.SetProject()
      self.GetIamPolicy()
      self.GetIamServiceAccounts()
      self.GetServicesList()
      self.GetComputeInstances()
    else:
      log.error('error: project name is not set.')

  def __BuildCmd(self, verb=None):
    """Command line builder.

    Args:
      verb (string): gcloud cli tool verb, e.g. 'iam service-accounts list'

    Returns:
      string: gcloud cli tool command string
    """
    if verb:
      return '{0:s} {1:s} {2:s}'.format(self.gcloud_cmd,
                                        self.common_options, verb)

  def GetIamServiceAccounts(self):
    """Gets gcloud IAM service accounts.

    Returns:
      string: JSON encoded list of IAM service accounts
    """
    log.info(('getting service accounts '
              'for project: \'{0:s}\'').format(self.project))
    self.iam_svc_accounts = None
    with fab.hide('running'):
      status = fab.local(self.__BuildCmd(verb='iam service-accounts list'),
                         capture=True)

      try:
        self.iam_svc_accounts = json.loads(status.stdout)
      except ValueError as e:
        print('Error parsing json returned by gcloud cli tool: {0:s}'.format(e))
        traceback.print_tb(sys.exc_info()[2])

  def GetServicesList(self):
    """Gets list of enabled gcloud services.

    Returns:
      string: JSON encoded list of enabled gcloud services
    """
    log.info(('getting enabled services '
              'for project: \'{0:s}\'').format(self.project))
    self.svcs_list = None
    self.svcs_list_full = None
    with fab.hide('running'):
      status = fab.local(self.__BuildCmd(verb='services list'), capture=True)

      try:
        self.svcs_list_full = json.loads(status.stdout)
      except ValueError as e:
        print('Error parsing json returned by gcloud cli tool: {0:s}'.format(e))
        traceback.print_tb(sys.exc_info()[2])

      self.svcs_list = list()

      for entry in self.svcs_list_full:
        self.svcs_list.append(entry['serviceName'])

  def GetComputeInstances(self):
    """Gets list of gcloud compute instances.

    Returns:
      string: JSON encoded data structure of gcloud compute instances
    """
    log.info(('getting compute instances '
              'for project: \'{0:s}\'').format(self.project))
    self.compute_instances = None
    self.compute_instances_full = None

    with fab.hide('running'):
      status = fab.local(self.__BuildCmd(verb='compute instances list'),
                         capture=True)

      try:
        self.compute_instances_full = json.loads(status.stdout)
      except ValueError as e:
        print('Error parsing json returned by gcloud cli tool: {0:s}'.format(e))
        traceback.print_tb(sys.exc_info()[2])

      self.compute_instances = list()

      for entry in self.compute_instances_full:
        self.compute_instances.append(entry['name'])

  def GetIamPolicy(self):
    """Gets IAM policy for gcloud project.

    Returns:
      string: JSON encoded iam policy
    """
    log.info(('getting iam policy for project: '
              '\'{0:s}\'').format(self.project))
    with fab.hide('running'):
      status = fab.local(self.__BuildCmd(verb=('projects get-iam-policy {0:s}'
                                              ).format(self.project)),
                         capture=True)

      try:
        self.iam_policy = json.loads(status.stdout)
      except ValueError as e:
        print('Error parsing json returned by gcloud cli tool: {0:s}'.format(e))
        traceback.print_tb(sys.exc_info()[2])

  def SetProject(self):
    """Sets project name for gcloud cmd object."""
    log.info('setting project to: \'{0:s}\''.format(self.project))
    with fab.hide('running'):
      status = fab.local(('gcloud config set '
                          'project {0:s}').format(self.project),
                         capture=True)
      if not status.stderr.startswith('Updated property [core/project].'):
        log.error('error setting project. got: \'{0:s}\''.format(status.stderr))

  def CreateServiceAccount(self):
    """Gets IAM policy for gcloud project."""
    for acct in self.iam_svc_accounts:
      acct_name = os.path.basename(acct['name'])
      log.debug(acct_name)
      if acct_name.startswith('{0:s}@'.format(self.svc_account_name)):
        self.svc_account = acct_name
      if self.svc_account and acct not in self.iam_svc_accounts:
        with fab.hide('running'):
          status = fab.local('gcloud iam service-accounts create {0:s} '
                             '--display-name {0:s}'.format(self.svc_account),
                             capture=True)

  def __HasRole(self, account_name=None, role=None):
    """Searches for role assigned to account_name in IAM policy.

    Args:
      account_name (string): name of account to check for role
      role (string): role to search for

    Returns:
      boolean indicate if account name has associated role
    """
    log.debug(('looking for account \'{0:s}\' in role '
               '\'{1:s}\'').format(account_name, role))
    found = False

    if not self.iam_policy:
      return None

    for binding in self.iam_policy['bindings']:
      log.debug('role: {0:s}'.format(binding['role']))
      log.debug('members: {0:s}'.format(binding['members']))
      if role == binding['role']:
        for member in binding['members']:
          if account_name == member.split(':')[1]:
            found = True
            break
        break

    return found

  def SetRequiredRoles(self):
    """Sets roles for self.account_name in IAM policy."""
    log.info('attempting to set roles')

    if self.required_roles and self.svc_account:
      for role in self.required_roles:
        log.info('checking role \'{0:s}\':'.format(role))
        if self.__HasRole(self.svc_account, role):
          log.info(('account: \'{0:s}\' present in role: '
                    '\'{1:s}\'. not adding.').format(self.svc_account,
                                                     role))
        else:
          log.info(('account: \'{0:s}\' not present in role: '
                    '\'{1:s}\'. adding.').format(self.svc_account,
                                                 role))
          with fab.hide('running'):
            status = fab.local(('gcloud projects add-iam-policy-binding {0:s} '
                                '--member serviceAccount:{1:s} '
                                '--role {2:s}').format(self.project,
                                                       self.svc_account,
                                                       role),
                               capture=True)

  def EnableRequiredServices(self, required_services=None):
    """Enables services for project.

    Args:
      required_services (list): services to be enabled
    """
    log.info('attempting to enable services')

    if required_services and self.svcs_list:
      for service in required_services:
        log.info('checking service \'{0:s}\''.format(service))
        if service in self.svcs_list:
          log.info('service: \'{0:s}\' already enabled.'.format(service))
        else:
          log.info('service: \'{0:s}\' disabled. enabling.'.format(service))
          with fab.hide('running'):
            status = fab.local(('gcloud services enable {0:s} '
                                '--project={1:s}').format(service,
                                                          self.project),
                               capture=True)

  def CreateServiceAccountKeys(self):
    """Create service account keys."""
    if os.path.exists(self.svc_account_keys_file):
      log.info(('keys file found at: \'{0:s}\'. '
                'not creating.').format(self.svc_account_keys_file))
    else:
      log.info(('keys file not found at: \'{0:s}\'. '
                'creating.').format(self.svc_account_keys_file))
      with fab.hide('running'):
        status = fab.local(('gcloud iam service-accounts keys create {0:s} '
                            '--iam-account={1:s}').format(
                                self.svc_account_keys_file,
                                self.svc_account),
                           capture=True)

  def GetInstanceStatus(self, instance=None):
    """Get status of compute instance.

    Args:
      instance (string): name of instance

    Returns:
      string containing instance status
    """
    status = None

    with fab.hide('running'):
      status = fab.local(('gcloud compute instances list '
                          '--format=json '
                          '--filter=\'name={0:s}\' ').format(instance),
                         capture=True)
      try:
        instance_status = json.loads(status.stdout)
      except ValueError as e:
        print('Error parsing json returned by gcloud cli tool: {0:s}'.format(e))
        traceback.print_tb(sys.exc_info()[2])

      if instance_status:
        status = instance_status[0].get('status', None)

    return status

  def GetInstances(self):
    """Get compute instances.

    Returns:
      compute instances data structure (dict of lists)
    """
    return self.instances

  def GetInstancesList(self, fully_qualified=False):
    """Get compute instances.

    Args:
      fully_qualified: boolean determining whether or not instances
                       names are fully qualified

    Returns:
      compute instances data structure (dict of lists)
    """
    instances = self.instances_list

    if fully_qualified:
      instances = list()
      for instance in self.instances_list:
        instances.append('{0:s}.{1:s}.{2:s}'.format(instance,
                                                    self.zone,
                                                    self.project))

    return instances

  def SetInstances(self):
    """Set compute instances."""
    self.instances = dict()
    self.instances['servers'] = list()
    self.instances['servers'].append('{0:s}-{1:s}-01'.format(self.name_prefix,
                                                             self.server))
    self.instances['workers'] = list()

    self.instances_list = list()

    for pidx in range(0, self.worker_pool_size):
      name = '{0:s}-{1:s}-{2:02d}'.format(self.name_prefix,
                                          self.worker_prefix, pidx+1)
      self.instances['workers'].append(name)

    for instance in self.instances.itervalues():
      self.instances_list.extend(instance)

  def CreateInstances(self):
    """Creates compute instances for project."""
    log.info('attempting to create instances')

    if self.instances_list and self.compute_instances:
      for instance_name in self.instances_list:
        log.info('checking instance \'{0:s}\''.format(instance_name))
        if instance_name in self.compute_instances:
          log.info('instance: \'{0:s}\' already created.'.format(instance_name))
        else:
          log.info(('instance: \'{0:s}\' nonexistent. '
                    'creating.').format(instance_name))
          with fab.hide('running'):
            status = fab.local(('gcloud compute instances create {0:s} '
                                '--zone={1:s} '
                                '--boot-disk-size={2:s} '
                                '--image-family={3:s} '
                                '--image-project={4:s} '.format(
                                    instance_name,
                                    self.zone,
                                    self.disk_size,
                                    self.image_family,
                                    self.image_project)),
                               capture=True)

  def StartInstance(self, instance=None):
    """Start compute instance.

    Args:
      instance (string): name of instance to be started
    """
    log.info('attempting to start instance {0:s}'.format(instance))
    instance_status = self.GetInstanceStatus(instance)
    if instance_status:
      if instance_status == 'RUNNING':
        log.info('instance \'{0:s}\' already running'.format(instance))
      else:
        with fab.hide('running'):
          status = fab.local(('gcloud compute instances start {0:s} '
                              '--zone={1:s}').format(instance, self.zone),
                             capture=True)
          instance_status = self.GetInstanceStatus(instance)
          if instance_status and instance_status == 'RUNNING':
            log.info('instance \'{0:s}\' started'.format(instance))
          else:
            log.warn('instance \'{0:s}\' not started'.format(instance))
    else:
      log.info('unable to get status for \'{0:s}\''.format(instance))

  def StartInstances(self):
    log.info('attempting to start instances')
    for instance in self.instances_list:
      self.StartInstance(instance)

  def SetupComputeSsh(self):
    """Set up gcloud compute ssh config."""
    ssh_key_file_path = self.gce_ssh_key_file

    if os.path.exists(ssh_key_file_path):
      log.info(('compute ssh private key already generated: '
                '\'{0:s}\'').format(ssh_key_file_path))
    else:
      status = fab.local(('ssh-keygen -b 4096 -t rsa -N \'\' '
                          '-C \'{0:s}@gcp\' -f {1:s}').format(
                              os.getenv('USER'),
                              ssh_key_file_path),
                         capture=True)

    with fab.hide('running'):
      status = fab.local('gcloud compute config-ssh',
                         capture=True)


def BuildWheels(opts):
  """Build/fetch python wheels for turbinia and plaso.

  Args:
    opts (dict): cli options data structure
  """
  with fab.hide('running'):
    log.info('building plaso wheels locally')
    fab.local(('curl -o {0:s}/plaso-reqts.txt '
               'https://raw.githubusercontent.com/'
               'log2timeline/plaso/master/requirements.txt').format(opts.cache))
    fab.local(('pip wheel --wheel-dir={0:s} '
               '-r {0:s}/plaso-reqts.txt').format(opts.cache))

    log.info('building turbinia wheels locally')
    fab.local(('curl -o {0:s}/turbinia-reqts.txt '
               'https://raw.githubusercontent.com/google/'
               'turbinia/master/requirements.txt').format(opts.cache))
    fab.local(('pip wheel --wheel-dir={0:s} '
               '-r {0:s}/turbinia-reqts.txt').format(opts.cache))

    log.info('fetching turbinia dependency wheels')
    fab.local('pip wheel --wheel-dir={0:s} '
              'pyasn1 pyasn1-modules google-auth-oauthlib '
              'google-cloud'.format(opts.cache))


def LocalSetup(opts):
  """Setup up local OS for turbinia.

  Args:
    opts (dict): cli options data structure
  """
  with fab.hide('running'):
    log.info('creating local tmp and cache directories')
    fab.local('install -d {0:s}'.format(opts.cache))

    log.info('installing local dependencies')
    fab.local('sudo apt-get -fy install build-essential git '
              'liblzma-dev python-dev python-virtualenv '
              'python-pip python-openssl')

    log.info('upgrading local pip')
    fab.local('sudo pip install --upgrade pip')

    log.info('installing local wheel')
    fab.local('sudo pip install wheel')


def RemoteOsSetup(host=None):
  """Setup up OS on remote host for turbinia.

  Args:
    host (string): hostname for remote host
  """
  if host:
    log.info('performing operations on host: {0:s}'.format(host))
    with fab.hide('running'):
      with fab.settings(host_string=host,
                        output_prefix=False,
                        timeout=3,
                        connection_attempts=60):

        log.info('updating remote apt sources.list')
        fab.sudo('perl -pi -e \x27s/^(deb.+main)$/$1 contrib non-free/\x27 '
                 '/etc/apt/sources.list')

        log.info('installing remote os updates')
        fab.sudo('apt-get -y update; apt-get -fy dist-upgrade')

        log.info('installing remote dependencies')
        fab.sudo('apt-get -fy install python-virtualenv git liblzma-dev '
                 'rsync python-pip python-wheel socat pv vim-nox sudo '
                 'wget curl python-openssl')

        log.info('upgrading remote pip')
        fab.sudo('pip install --upgrade pip')
        log.info('installing remote wheel')
        fab.sudo('pip install wheel')


def RemoteTurbiniaSetup(opts, host=None):
  """Setup up remote host for turbinia.

  Args:
    opts (dict): cli options data structure
    host (string): hostname for remote host
  """
  remote_cache = opts.cache
  date_suffix = time.strftime('%Y%m%d_%H%M%S')
  if host:
    log.info('performing operations on host: {0:s}'.format(host))
    with fab.hide('running'):
      with fab.settings(host_string=host,
                        output_prefix=False,
                        timeout=3,
                        connection_attempts=60):
        log.info('installing remote plaso')
        fab.sudo(('sudo pip install --use-wheel --no-index --find-links={0:s} '
                  '-r {0:s}/plaso-reqts.txt plaso').format(remote_cache))

        log.info('updating turbinia directory')
        fab.sudo('mv {0:s}/turbinia {1:s}-{2:s}'.format(opts.tmpdir,
                                                        opts.tdir, date_suffix))
        # remove old symlink
        fab.sudo('rm {0:s} > /dev/null 2>&1 || true'.format(opts.tdir))

        # update to symlink to new directory
        fab.sudo('ln -s {0:s}-{1:s} {0:s}'.format(opts.tdir, date_suffix))
        with fab.cd(opts.tdir):
          log.info('installing remote turbinia')
          fab.sudo(('sudo pip install --use-wheel --no-index '
                    '--find-links={0:s} '
                    '-r {0:s}/turbinia-reqts.txt').format(remote_cache))

        # ensure google oauthlib and python asn1 modules are fully upgraded to
        # avoid:
        # from pyasn1.type import opentype
        # ImportError: cannot import name 'opentype'
        fab.sudo(('pip install  --use-wheel --no-index '
                  '--find-links={0:s} '
                  '--upgrade pyasn1 pyasn1-modules '
                  'google-auth-oauthlib google-cloud').format(remote_cache))


def InstallTurbinia(opts, instances):
  """Install turbinia on compute instances.

  Args:
    opts (argparse namespace class): cli options data structure
    instances (list): list of instances to install turbinia on
  """
  for host in instances:
    try:
      with fab.settings(host_string=host,
                        output_prefix=False,
                        timeout=3,
                        connection_attempts=60):

        RemoteOsSetup(host)
        log.info('copying turbinia to host: {0:s}'.format(host))
        fabp.rsync_project(local_dir=opts.troot,
                           remote_dir='{0:s}/'.format(opts.tmpdir),
                           extra_opts='-P',
                           ssh_opts='-o \"stricthostkeychecking no\"')
        log.info('copying wheels cache to host: {0:s}'.format(host))
        fabp.rsync_project(local_dir='{0:s}/*'.format(opts.cache),
                           remote_dir=opts.cache,
                           extra_opts='-P',
                           ssh_opts='-o \"stricthostkeychecking no\"')
        RemoteTurbiniaSetup(opts, host)
        fab.sudo('chown -R 0:0 {0:s}'.format(opts.tdir))

        # prune remote
        if opts.no_prune_tc:
          log.info(('host: {0:s} - not pruning cache ({1:s}) and '
                    'tmp ({2:s}) directories').format(host,
                                                      opts.cache,
                                                      opts.tmpdir))
        else:
          fab.run('rm -fr {0:s} {1:s}'.format(opts.cache, opts.tmpdir))
    except FabNetworkError:
      log.error('unable to connect to server')

  # prune local
  if opts.no_prune_tc:
    log.info(('not pruning cache ({0:s}) directory ').format(opts.cache))
  else:
    shutil.rmtree(opts.cache)


def main():
  """main function."""
  opts = Init()
  LocalSetup(opts)

  turbinia_cloud = GcloudCmd(opts)
  turbinia_cloud.CreateServiceAccount()
  turbinia_cloud.SetRequiredRoles()
  turbinia_cloud.CreateServiceAccountKeys()
  turbinia_cloud.EnableRequiredServices()

  turbinia_cloud.SetInstances()

  turbinia_cloud.CreateInstances()
  turbinia_cloud.StartInstances()

  turbinia_cloud.SetupComputeSsh()

  BuildWheels(opts)

  InstallTurbinia(opts, turbinia_cloud.GetInstancesList(fully_qualified=True))

  log.info('Install completed.')


if __name__ == '__main__':
  main()
