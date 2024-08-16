# -*- coding: utf-8 -*-
# Copyright 2022 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Turbinia API client command-line tool."""

import os
import sys
import logging
import click

from urllib3 import exceptions as urllib3_exceptions

from turbinia_client.turbiniacli import TurbiniaCli
from turbinia_client.core import groups
from turbinia_client.core.commands import version

_LOGGER_FORMAT = '%(asctime)s %(levelname)s %(name)s - %(message)s'
logging.basicConfig(format=_LOGGER_FORMAT, level=logging.INFO)
log = logging.getLogger(__name__)


@click.group(context_settings={
    'help_option_names': ['-h', '--help'],
})
@click.option(
    '--config_instance', '-c', help='A Turbinia instance configuration name.',
    show_default=True, show_envvar=True, type=str,
    default=lambda: os.environ.get('TURBINIA_CONFIG_INSTANCE', 'default'))
@click.option(
    '--config_path', '-p', help='Path to the .turbinia_api_config.json file.',
    show_default=True, show_envvar=True, type=str,
    default=lambda: os.environ.get('TURBINIA_API_CONFIG_PATH', '~'))
@click.pass_context
def cli(ctx: click.Context, config_instance: str, config_path: str) -> None:
  """Turbinia API command-line tool (turbinia-client).
  
  \b                         ***    ***                                       
  \b                          *          *                                      
  \b                     ***             ******                                 
  \b                    *                      *                                
  \b                    **      *   *  **     ,*                                
  \b                      *******  * ********                                  
  \b                             *  * *                                         
  \b                             *  * *                                         
  \b                             %%%%%%                                         
  \b                             %%%%%%                                         
  \b                    %%%%%%%%%%%%%%%       %%%%%%                            
  \b              %%%%%%%%%%%%%%%%%%%%%      %%%%%%%                            
  \b %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%  ** *******       
  \b %%                                                   %%  ***************   
  \b %%                                (%%%%%%%%%%%%%%%%%%%  *****  **          
  \b   %%%%%        %%%%%%%%%%%%%%%                                             
                                              
  \b   %%%%%%%%%%                     %%          **             ***              
  \b      %%%                         %%  %%             %%%           %%%%,      
  \b      %%%      %%%   %%%   %%%%%  %%%   %%%   %%  %%%   %%%  %%%       (%%    
  \b      %%%      %%%   %%%  %%%     %%     %%/  %%  %%%   %%%  %%%  %%%%%%%%    
  \b      %%%      %%%   %%%  %%%     %%%   %%%   %%  %%%   %%%  %%% %%%   %%%    
  \b      %%%        %%%%%    %%%       %%%%%     %%  %%%    %%  %%%   %%%%%      

  This command-line tool interacts with Turbinia's API server.

  You can specify the API server location in ~/.turbinia_api_config.json
  """
  ctx.obj = TurbiniaCli(
      config_instance=config_instance, config_path=config_path)

  # Set up the tool based on the configuration file parameters.
  ctx.obj.setup()


def main():
  """Initialize the cli application."""

  # Register all command groups.
  cli.add_command(groups.submit_group)
  cli.add_command(groups.evidence_group)
  cli.add_command(groups.config_group)
  cli.add_command(groups.jobs_group)
  cli.add_command(groups.result_group)
  cli.add_command(groups.status_group)
  cli.add_command(groups.report_group)
  cli.add_command(groups.logs_group)
  cli.add_command(version)
  try:
    cli.main()
  except (ConnectionRefusedError, urllib3_exceptions.MaxRetryError,
          urllib3_exceptions.NewConnectionError) as exception:
    log.error(f'Error connecting to the Turbinia API server: {exception!s}')
    sys.exit(-1)


main()
