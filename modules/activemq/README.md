# Deprecation notice

This module was designed for Puppet versions 2 and 3. It should work also on Puppet 4 but doesn't use any of its features.

The current Puppet 3 compatible codebase is no longer actively maintained by example42.

Still, Pull Requests that fix bugs or introduce backwards compatible features will be accepted.



# Puppet module: activemq

This is a Puppet module for activemq based on the second generation layout ("NextGen") of Example42 Puppet Modules.

Made by Alessandro Franceschi / Lab42

Official site: http://www.example42.com

Official git repository: http://github.com/example42/puppet-activemq

Module enhancements sponsored by [AllOver.IO](http://www.allover.io)

Released under the terms of Apache 2 License.

This module requires functions provided by the Example42 Puppi module (you need it even if you don't use and install Puppi)

For detailed info about the logic and usage patterns of Example42 modules check the DOCS directory on Example42 main modules set.

This module is based on ActiveMQ packages provided by the PuppetLabs repository.
For RedHat derivatives it requires Example42's yum module (or at least yum/manifests/repo/puppetlabs.pp).

## USAGE - Basic management

* Install activemq with default settings

        class { 'activemq': }

* Install activemq without including the (needed) dependencies that rely on other Example42 modules. When you set install_dependencies to false you need to provide in some way the equivant of what is placed in activemq/manifests/dependencies.pp

        class { 'activemq':
          install_dependencies => false,
        }

* Install activemq directly from upstream site. Must specify the wanted version. Also, by default, an activemq user is created which runs the service

        class { 'activemq':
          install             => 'source',
          version             => '5.8.0',
          install_destination => '/opt',      # Default value
          create_user         => true,        # Default value
          process_user        => 'activemq',  # Default value
        }

* Install a specific version of activemq package

        class { 'activemq':
          version => '1.0.1',
        }

* Disable activemq service.

        class { 'activemq':
          disable => true
        }

* Remove activemq package

        class { 'activemq':
          absent => true
        }

* Enable auditing without without making changes on existing activemq configuration files

        class { 'activemq':
          audit_only => true
        }


## USAGE - Overrides and Customizations
* Use custom sources for main config file 

        class { 'activemq':
          source => [ "puppet:///modules/lab42/activemq/activemq.conf-${hostname}" , "puppet:///modules/lab42/activemq/activemq.conf" ], 
        }


* Use custom source directory for the whole configuration dir

        class { 'activemq':
          source_dir       => 'puppet:///modules/lab42/activemq/conf/',
          source_dir_purge => false, # Set to true to purge any existing file not present in $source_dir
        }

* Use custom template for main config file. Note that template and source arguments are alternative. 

        class { 'activemq':
          template => 'example42/activemq/activemq.conf.erb',
        }

* Automatically include a custom subclass

        class { 'activemq':
          my_class => 'activemq::example42',
        }


## USAGE - Example42 extensions management 
* Activate puppi (recommended, but disabled by default)

        class { 'activemq':
          puppi    => true,
        }

* Activate puppi and use a custom puppi_helper template (to be provided separately with a puppi::helper define ) to customize the output of puppi commands 

        class { 'activemq':
          puppi        => true,
          puppi_helper => 'myhelper', 
        }

* Activate automatic monitoring (recommended, but disabled by default). This option requires the usage of Example42 monitor and relevant monitor tools modules

        class { 'activemq':
          monitor      => true,
          monitor_tool => [ 'nagios' , 'monit' , 'munin' ],
        }

* Activate automatic firewalling. This option requires the usage of Example42 firewall and relevant firewall tools modules

        class { 'activemq':       
          firewall      => true,
          firewall_tool => 'iptables',
          firewall_src  => '10.42.0.0/24',
          firewall_dst  => $ipaddress_eth0,
        }


[![Build Status](https://travis-ci.org/example42/puppet-activemq.png?branch=master)](https://travis-ci.org/example42/puppet-activemq)
