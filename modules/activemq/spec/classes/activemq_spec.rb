require 'spec_helper'
#require "#{File.join(File.dirname(__FILE__),'..','spec_helper.rb')}"

describe 'activemq' do

  let(:title) { 'activemq' }
  let(:node) { 'rspec.example42.com' }
  let(:facts) { {
      :ipaddress => '10.42.42.42',
      :operatingsystem => 'CentOS',
      :operatingsystemrelease => '10.10',
      :fqdn => 'rspec.example42.com'
  } }

  describe 'Test standard installation' do
    it { should contain_package('activemq').with_ensure('present') }
    it { should contain_service('activemq').with_ensure('running') }
    it { should contain_service('activemq').with_enable('true') }
    it { should contain_file('activemq.conf').with_ensure('present') }
  end

  describe 'Test installation of a specific version' do
    let(:params) { {:version => '1.0.42' } }
    it { should contain_package('activemq').with_ensure('1.0.42') }
  end

  describe 'Test standard installation with monitoring and firewalling' do
    let(:params) { {:monitor => true , :firewall => true, :port => '42', :protocol => 'tcp' } }

    it { should contain_package('activemq').with_ensure('present') }
    it { should contain_service('activemq').with_ensure('running') }
    it { should contain_service('activemq').with_enable('true') }
    it { should contain_file('activemq.conf').with_ensure('present') }
    it { should contain_monitor__process('activemq_process').with_enable('true') }
    it { should contain_firewall('activemq_tcp_42').with_enable('true') }
  end

  describe 'Test decommissioning - absent' do
    let(:params) { {:absent => true, :monitor => true , :firewall => true, :port => '42', :protocol => 'tcp'} }

    it 'should remove Package[activemq]' do should contain_package('activemq').with_ensure('absent') end 
    it 'should stop Service[activemq]' do should contain_service('activemq').with_ensure('stopped') end
    it 'should not enable at boot Service[activemq]' do should contain_service('activemq').with_enable('false') end
    it 'should remove activemq configuration file' do should contain_file('activemq.conf').with_ensure('absent') end
    it { should contain_monitor__process('activemq_process').with_enable('false') }
    it { should contain_firewall('activemq_tcp_42').with_enable('false') }
  end

  describe 'Test decommissioning - disable' do
    let(:params) { {:disable => true, :monitor => true , :firewall => true, :port => '42', :protocol => 'tcp'} }

    it { should contain_package('activemq').with_ensure('present') }
    it 'should stop Service[activemq]' do should contain_service('activemq').with_ensure('stopped') end
    it 'should not enable at boot Service[activemq]' do should contain_service('activemq').with_enable('false') end
    it { should contain_file('activemq.conf').with_ensure('present') }
    it { should contain_monitor__process('activemq_process').with_enable('false') }
    it { should contain_firewall('activemq_tcp_42').with_enable('false') }
  end

  describe 'Test decommissioning - disableboot' do
    let(:params) { {:disableboot => true, :monitor => true , :firewall => true, :port => '42', :protocol => 'tcp'} }
  
    it { should contain_package('activemq').with_ensure('present') }
    it { should_not contain_service('activemq').with_ensure('present') }
    it { should_not contain_service('activemq').with_ensure('absent') }
    it 'should not enable at boot Service[activemq]' do should contain_service('activemq').with_enable('false') end
    it { should contain_file('activemq.conf').with_ensure('present') }
    it { should contain_monitor__process('activemq_process').with_enable('false') }
    it { should contain_firewall('activemq_tcp_42').with_enable('true') }
  end 

  describe 'Test customizations - template' do
    let(:params) { {:template => "activemq/spec.erb" , :options => { 'opt_a' => 'value_a' } } }

    it { should contain_file('activemq.conf').with_content(/fqdn: rspec.example42.com/) }
    it { should contain_file('activemq.conf').with_content(/value_a/) }

  end

  describe 'Test customizations - source' do
    let(:params) { {:source => "puppet://modules/activemq/spec" , :source_dir => "puppet://modules/activemq/dir/spec" , :source_dir_purge => true } }

    it { should contain_file('activemq.conf').with_source('puppet://modules/activemq/spec') }
    it 'should request a valid source dir' do
      should contain_file('activemq.dir').with_source("puppet://modules/activemq/dir/spec")
      #content = catalogue.resource('file', 'activemq.dir').send(:parameters)[:source]
      #content.should == "puppet://modules/activemq/dir/spec"
    end
    it 'should purge source dir if source_dir_purge is true' do
      should contain_file('activemq.dir').with_ensure('directory')
      #content = catalogue.resource('file', 'activemq.dir').send(:parameters)[:purge]
      #content.should == true
    end
  end

  describe 'Test customizations - custom class' do
    let(:params) { {:my_class => "activemq::spec" } }
    it 'should automatically include a custom class' do
      should contain_file('activemq.conf').with_content(/fqdn: rspec.example42.com/)
      #content = catalogue.resource('file', 'activemq.conf').send(:parameters)[:content]
      #content.should match "fqdn: rspec.example42.com"
    end
  end

  describe 'Test service autorestart' do
    let(:params) { {:service_autorestart => "no" } }

    it 'should not automatically restart the service, when service_autorestart => false' do
      should contain_file('activemq.conf').with_content(nil)
      #content = catalogue.resource('file', 'activemq.conf').send(:parameters)[:notify]
      #content.should be_nil
    end
  end

  describe 'Test Puppi Integration' do
    let(:params) { {:puppi => true, :puppi_helper => "myhelper"} }

    it 'should generate a puppi::ze define' do
      should contain_puppi__ze('activemq').with_content(nil)
      #content = catalogue.resource('puppi::ze', 'activemq').send(:parameters)[:helper]
      #content.should == "myhelper"
    end
  end

  describe 'Test Monitoring Tools Integration' do
    let(:params) { {:monitor => true, :monitor_tool => "puppi" } }

    it 'should generate monitor defines' do
      should contain_monitor__process('activemq_process').with_content(nil)
      #content = catalogue.resource('monitor::process', 'activemq_process').send(:parameters)[:tool]
      #content.should == "puppi"
    end
  end

  describe 'Test Firewall Tools Integration' do
    let(:params) { {:firewall => true, :firewall_tool => "iptables" , :protocol => "tcp" , :port => "42" } }

    it 'should generate correct firewall define' do
      should contain_firewall('activemq_tcp_42').with_content(nil)
      #content = catalogue.resource('firewall', 'activemq_tcp_42').send(:parameters)[:tool]
      #content.should == "iptables"
    end
  end

  describe 'Test OldGen Module Set Integration' do
    let(:params) { {:monitor => "yes" , :monitor_tool => "puppi" , :firewall => "yes" , :firewall_tool => "iptables" , :puppi => "yes" , :port => "42" , :protocol => 'tcp' } }

    it 'should generate monitor resources' do
      should contain_monitor__process('activemq_process').with_content(nil)
      #content = catalogue.resource('monitor::process', 'activemq_process').send(:parameters)[:tool]
      #content.should == "puppi"
    end
    it 'should generate firewall resources' do
      should contain_firewall('activemq_tcp_42').with_content(nil)
      #content = catalogue.resource('firewall', 'activemq_tcp_42').send(:parameters)[:tool]
      #content.should == "iptables"
    end
    it 'should generate puppi resources ' do 
      should contain_puppi__ze('activemq').with_content(nil)
      #content = catalogue.resource('puppi::ze', 'activemq').send(:parameters)[:ensure]
      #content.should == "present"
    end
  end

  describe 'Test params lookup' do
    let(:facts) { { :monitor => true , :ipaddress => '10.42.42.42' } }
    let(:params) { { :port => '42' } }

    it 'should honour top scope global vars' do
      should contain_monitor__process('activemq_process').with_content(nil)
      #content = catalogue.resource('monitor::process', 'activemq_process').send(:parameters)[:enable]
      #content.should == true
    end
  end

  describe 'Test params lookup' do
    let(:facts) { { :activemq_monitor => true , :ipaddress => '10.42.42.42' } }
    let(:params) { { :port => '42' } }

    it 'should honour module specific vars' do
      should contain_monitor__process('activemq_process').with_content(nil)
      #content = catalogue.resource('monitor::process', 'activemq_process').send(:parameters)[:enable]
      #content.should == true
    end
  end

  describe 'Test params lookup' do
    let(:facts) { { :monitor => false , :activemq_monitor => true , :ipaddress => '10.42.42.42' } }
    let(:params) { { :port => '42' } }

    it 'should honour top scope module specific over global vars' do
      should contain_monitor__process('activemq_process').with_content(nil)
      #content = catalogue.resource('monitor::process', 'activemq_process').send(:parameters)[:enable]
      #content.should == true
    end
  end

  describe 'Test params lookup' do
    let(:facts) { { :monitor => false , :ipaddress => '10.42.42.42' } }
    let(:params) { { :monitor => true , :firewall => true, :port => '42' } }

    it 'should honour passed params over global vars' do
      should contain_monitor__process('activemq_process').with_content(nil)
      #content = catalogue.resource('monitor::process', 'activemq_process').send(:parameters)[:enable]
      #content.should == true
    end
  end

end

