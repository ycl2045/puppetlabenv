for collective in mcollective ; do
	  rabbitmqadmin declare exchange --user=admin --password=yunjikeji --vhost=/mcollective name=${collective}_broadcast type=topic
  rabbitmqadmin declare exchange --user=admin --password=yunjikeji --vhost=/mcollective name=${collective}_directed type=direct
done
