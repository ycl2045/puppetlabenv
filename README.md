# puppetlabenv
# puppetlabenv

* step 1  安装必要的远程库

  rpm -ivh puppet5-release-el-7.noarch.rpm 
  rpm -ivh epel-release-latest-7.noarch.rpm

* step 2  安装 puppet agent

  yuddm install puppet-agent -y

* step 3  安装 puppetserver 及相关组件
  
  puppet apply --modulepath=modules puppetserver.yaml
  
  puppet apply --modulepath=modules puppetdb.yaml

* step4  安装 mcollective 相关组件

  puppet apply --modulepath=modules rabbitmq.yaml

  puppet apply --modulepath=modules mcollective.yaml

  puppet apply --modulepath=modules mcollective_plugin.yaml
